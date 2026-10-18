"""
The orchestrator: one URL in, one ScanResult out.

    normalise URL → (cache?) → fetch safely → parse → run rules
                 → threat-list lookup → features → model → verdict

`analyse()` is the pure, offline half of the pipeline. Training, evaluation
and tests call it directly with pages they already have, which guarantees the
model is evaluated on exactly the code path users run.
"""

from __future__ import annotations

import logging
import time

from preflight.cache import TTLCache
from preflight.config import AppConfig
from preflight.context import ScanContext
from preflight.detectors import ThreatIntel, run_detectors
from preflight.features import URL_FEATURE_NAMES, extract_feature_dict, to_vector
from preflight.ml.model import ModelMismatchError, RiskModel
from preflight.net import SafeFetcher
from preflight.parsing import url_tools as ut
from preflight.schema import FetchedPage, ScanResult, Verdict
from preflight.scoring import decide

log = logging.getLogger(__name__)

SCAN_MODES = ("full", "url_only")


class Scanner:
    def __init__(self, config: AppConfig, model: RiskModel | None,
                 intel: ThreatIntel, fetcher: SafeFetcher | None = None) -> None:
        self.config = config
        self.model = model
        self.intel = intel
        self.fetcher = fetcher or SafeFetcher(config.fetch)
        self.cache: TTLCache[ScanResult] = TTLCache(config.cache_ttl_s, config.cache_max_entries)

    @classmethod
    def from_config(cls, config: AppConfig) -> "Scanner":
        """Build a scanner, loading the model and threat lists from disk."""
        model = None
        if config.model_path.exists():
            try:
                model = RiskModel.load(config.model_path)
            except ModelMismatchError as exc:
                log.warning("model not loaded (%s); running rules only", exc)
            except Exception as exc:  # noqa: BLE001 - e.g. saved with another scikit-learn version
                log.warning("model could not be loaded (%s: %s). Run `python train_model.py` "
                            "to rebuild it. Running rules only.", type(exc).__name__, exc)
        else:
            log.warning("no model at %s; run train_model.py. Running rules only.",
                        config.model_path)
        return cls(config, model, ThreatIntel.load(config.threat_data_dir))

    # ------------------------------------------------------------------ live
    def scan(self, raw_url: str, mode: str = "full") -> ScanResult:
        started = time.perf_counter()
        if mode not in SCAN_MODES:
            mode = "full"
        try:
            url = ut.normalise_url(raw_url)
        except ValueError as exc:
            return ScanResult(url=str(raw_url)[:500], verdict=Verdict.ERROR, risk_score=0.0,
                              ml_probability=None, notes=[str(exc)], mode=mode)

        cache_key = f"{mode}|{url}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            cached.from_cache = True
            return cached

        timings: dict[str, float] = {}
        if mode == "full":
            t0 = time.perf_counter()
            page = self.fetcher.fetch(url)
            context = ScanContext.build(url, page, self.intel.protected_domains, mode)
            if page.fetched_ok and context.doc.external_script_urls:
                page.external_scripts = self.fetcher.fetch_scripts(context.doc.external_script_urls)
            timings["fetch_ms"] = (time.perf_counter() - t0) * 1000
        else:
            page = FetchedPage(requested_url=url, final_url=url)
            context = ScanContext.build(url, page, self.intel.protected_domains, mode)

        result = self.analyse(url, page, mode=mode, context=context, timings=timings)
        result.timings_ms["total_ms"] = (time.perf_counter() - started) * 1000
        self.cache.put(cache_key, result)
        return result

    # --------------------------------------------------------------- offline
    def analyse(self, url: str, page: FetchedPage, *, mode: str = "full",
                context: ScanContext | None = None,
                timings: dict[str, float] | None = None) -> ScanResult:
        t0 = time.perf_counter()
        context = context or ScanContext.build(url, page, self.intel.protected_domains, mode)
        timings = dict(timings or {})

        findings, detector_errors = run_detectors(context)
        findings.extend(self.intel.check(page.redirect_chain or [url]))

        ml_probability, ml_factors, out_of_distribution = None, [], False
        if self.model is not None:
            vector = to_vector(extract_feature_dict(context))
            ml_probability = self.model.predict(vector)
            unusual = self.model.unusual_features(vector)
            out_of_distribution = len(unusual) >= self.config.scoring.ood_feature_limit
            if ml_probability >= self.config.scoring.uncertain_low:
                # Without page content, content features are absent rather than
                # "low", so only URL features may be used to explain the score.
                allowed = None if context.content_analysed else URL_FEATURE_NAMES
                ml_factors = self.model.explain(vector, top_k=self.config.scoring.max_ml_factors,
                                                only=allowed)

        outcome = decide(findings, ml_probability,
                         content_analysed=context.content_analysed,
                         out_of_distribution=out_of_distribution,
                         settings=self.config.scoring, mode=mode)

        # Domains in the trust-list are forced to a safe verdict; findings stay visible.
        if self.intel.is_trusted(page.redirect_chain or [url]):
            outcome.verdict = Verdict.SAFE
            outcome.notes = ["You marked this site as trusted, so PreFlight won't warn about it."]

        notes = self._fetch_notes(page, mode) + outcome.notes
        if detector_errors:
            notes.append("Some checks could not run on this page: " + "; ".join(detector_errors))

        timings["analysis_ms"] = (time.perf_counter() - t0) * 1000
        return ScanResult(
            url=url,
            verdict=outcome.verdict,
            risk_score=outcome.risk,
            ml_probability=ml_probability,
            findings=findings,
            ml_factors=ml_factors,
            notes=notes,
            final_url=page.final_url if page.redirect_chain else None,
            redirect_chain=list(page.redirect_chain),
            mode=mode,
            out_of_distribution=out_of_distribution,
            timings_ms=timings,
            model_info=self.provenance(),
        )

    def remember_site(self, url: str, *, block: bool) -> str:
        """Add the site's domain to the block-list (block=True) or trust-list
        (block=False), clear the result cache, and return the domain."""
        domain = self.intel.add_domain(url, block=block)
        self.cache.clear()
        return domain

    # ---------------------------------------------------------------- helpers
    def provenance(self) -> dict:
        """Where the scanner's knowledge comes from, and how old it is."""
        info = dict(self.model.info) if self.model else {"algorithm": None}
        age = self.intel.age_days()
        info["threat_list_entries"] = self.intel.size
        info["threat_list_age_days"] = None if age is None else round(age, 1)
        info["threat_list_sources"] = self.intel.sources
        return info

    def _fetch_notes(self, page: FetchedPage, mode: str) -> list[str]:
        notes = []
        if mode == "url_only":
            notes.append("URL-only mode: the page was not downloaded.")
        elif page.fetch_error:
            notes.append(f"Could not load the page: {page.fetch_error}.")
        if page.truncated:
            notes.append("The page was very large; only the first part was checked.")
        age = self.intel.age_days()
        # A missing feed is reported in provenance (shown in the pop-up footer);
        # a stale one is worth calling out on every result.
        if age is not None and age > self.config.threat_list_stale_days:
            notes.append(f"Threat list is {age:.0f} days old.")
        return notes
