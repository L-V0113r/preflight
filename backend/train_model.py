"""
Train PreFlight's model and save it to models/preflight_model.joblib.

    python train_model.py                          # synthetic data only
    python train_model.py --html-dir my_dataset    # add your own labelled HTML pages
    python train_model.py --url-csv urls.csv       # add labelled URLs (url,label)

The model card (models/MODEL_CARD.md) records what the model was trained on.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from preflight.config import default_config
from preflight.data import SyntheticWebFactory, load_html_folder, load_url_csv
from preflight.detectors import ThreatIntel
from preflight.ml import train_model
from preflight.ml.dataset import featurise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n-benign", type=int, default=4000)
    parser.add_argument("--n-malicious", type=int, default=2600)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--html-dir", type=Path, help="folder with benign/ and malicious/ HTML")
    parser.add_argument("--url-csv", type=Path, help="CSV with url,label columns")
    parser.add_argument("--out", type=Path, help="where to save the model")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = default_config()
    out_path = args.out or config.model_path
    intel = ThreatIntel.load(config.threat_data_dir)

    samples = SyntheticWebFactory(args.seed).generate(args.n_benign, args.n_malicious)
    sources = [f"{len(samples)} labelled synthetic pages (seed {args.seed})"]
    if args.html_dir:
        real = load_html_folder(args.html_dir)
        samples += real
        sources.append(f"{len(real)} real HTML pages from {args.html_dir}")
    if args.url_csv:
        urls = load_url_csv(args.url_csv)
        samples += urls
        sources.append(f"{len(urls)} real labelled URLs from {args.url_csv}")
    description = "; ".join(sources)

    print(f"Extracting features from {len(samples)} pages...")
    data = featurise(samples, intel.protected_domains)

    print("Selecting and calibrating the model (5-fold cross-validation)...")
    model, report = train_model(data.X, data.y, seed=args.seed, data_description=description)
    model.save(out_path)

    for name, (mean, std) in report.cv_scores.items():
        marker = "  <- chosen" if name == report.chosen else ""
        print(f"  {name:22s} average precision {mean:.4f} ± {std:.4f}{marker}")
    print(f"Saved {out_path} ({out_path.stat().st_size / 1024:.0f} KB) in {report.seconds:.1f}s.")

    card = out_path.parent / "MODEL_CARD.md"
    meta = model.bundle.metadata
    card.write_text("\n".join([
        "# PreFlight model card",
        "",
        f"- **Algorithm:** {meta['algorithm']} (scikit-learn {meta['sklearn_version']})",
        f"- **Trained:** {meta['trained_at']}",
        f"- **Training data:** {description}",
        f"- **Samples:** {meta['n_samples']} ({meta['n_malicious']} malicious)",
        f"- **Cross-validated average precision:** "
        + ", ".join(f"{k} {v[0]:.4f}" for k, v in meta["cv_average_precision"].items()),
        "",
        "## Intended use",
        "A second opinion, alongside rule checks, on whether a web page attacks its visitor.",
        "It runs locally and never sends the URL anywhere.",
        "",
        "## Not intended for",
        "Judging whether a site is honest, legal or good value; scanning sites you don't",
        "intend to visit; any decision about a person.",
        "",
        "## Known limits",
        "- Trained on synthetic pages unless real data was added (see above). Real-world",
        "  accuracy is unmeasured until it is evaluated on real, labelled pages.",
        "- Reads code statically, so heavily obfuscated or server-side cloaked attacks can be missed.",
        "- Unusual pages are flagged as 'unsure' using the feature ranges stored in the model.",
        "",
    ]), encoding="utf-8")
    (out_path.parent / "model_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Wrote {card}.")


if __name__ == "__main__":
    main()
