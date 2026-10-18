"""
Every tunable number in one place.

Settings are frozen dataclasses: they are created once at start-up and never
mutated, which makes the behaviour of a running scanner easy to reason about.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

# backend/ (the folder that contains the preflight package)
BACKEND_DIR = Path(__file__).resolve().parent.parent
THREAT_DATA_DIR = BACKEND_DIR / "threat_data"
MODELS_DIR = BACKEND_DIR / "models"
REPORTS_DIR = BACKEND_DIR / "reports"
SAMPLES_DIR = BACKEND_DIR / "samples"

# A realistic desktop browser user agent. Some phishing kits show harmless
# content to anything that looks like a bot ("cloaking"), so looking like a
# browser improves what we get back. It does not make cloaking impossible.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class FetchSettings:
    """Limits for downloading a page. All limits exist to stay safe and fast."""

    timeout_s: float = 8.0
    max_bytes: int = 2_000_000           # stop reading a page after ~2 MB
    max_redirects: int = 6
    max_external_scripts: int = 4        # third-party JS files we also inspect
    max_script_bytes: int = 300_000
    script_timeout_s: float = 4.0
    user_agent: str = DEFAULT_USER_AGENT
    # Only ever True for tests and the local demo. In normal use the scanner
    # refuses to fetch private/loopback addresses (see net/address_guard.py).
    allow_private_targets: bool = False


@dataclass(frozen=True)
class ScoringSettings:
    """Thresholds that turn scores into verdicts (see preflight/scoring.py)."""

    danger_threshold: float = 0.80
    caution_threshold: float = 0.45
    # If the model's probability is inside this band it is "on the fence".
    uncertain_low: float = 0.30
    uncertain_high: float = 0.60
    ml_weight: float = 0.90              # how far we trust the model alone
    # When only the link could be judged, the model has far less evidence, so
    # its opinion counts for less (it can raise CAUTION, never DANGER, alone).
    ml_weight_url_only: float = 0.50
    ood_feature_limit: int = 5           # features out of range => unfamiliar page
    max_ml_factors: int = 3


@dataclass(frozen=True)
class ServerSettings:
    host: str = "127.0.0.1"              # never 0.0.0.0: local machine only
    port: int = 8765
    token_path: Path = field(default_factory=lambda: Path.home() / ".preflight" / "token")
    max_request_bytes: int = 8_192
    verbose: bool = False                # if True, log scanned domains


@dataclass(frozen=True)
class AppConfig:
    fetch: FetchSettings = field(default_factory=FetchSettings)
    scoring: ScoringSettings = field(default_factory=ScoringSettings)
    server: ServerSettings = field(default_factory=ServerSettings)
    model_path: Path = MODELS_DIR / "preflight_model.joblib"
    threat_data_dir: Path = THREAT_DATA_DIR
    cache_ttl_s: float = 600.0
    cache_max_entries: int = 512
    # Days after which the local threat list is reported as stale.
    threat_list_stale_days: float = 2.0

    def with_fetch(self, **changes) -> "AppConfig":
        """Return a copy with some fetch settings changed (used by tests/demo)."""
        return replace(self, fetch=replace(self.fetch, **changes))

    def with_server(self, **changes) -> "AppConfig":
        return replace(self, server=replace(self.server, **changes))


def default_config() -> AppConfig:
    return AppConfig()
