"""
Evaluate PreFlight against baselines on a held-out synthetic test set and
write reports/evaluation_report.md (+ .json).

    python evaluate.py                 # full synthetic study (a few minutes)
    python evaluate.py --quick         # smaller data, skips leave-one-family-out
    python evaluate.py --real-dir dataset   # test the saved model on REAL labelled pages
                                            # (dataset/benign/*.html, dataset/malicious/*.html)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from preflight.config import REPORTS_DIR, default_config
from preflight.data import load_html_folder
from preflight.ml.evaluation import evaluate_real_folder, run_evaluation
from preflight.ml.report import write_report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=11,
                        help="use a different seed from training so test pages are new")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--real-dir", type=Path, help="folder with benign/ and malicious/ HTML")
    args = parser.parse_args()

    if args.real_dir:
        report = evaluate_real_folder(default_config(), load_html_folder(args.real_dir))
        report["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report["source_folder"] = str(args.real_dir)
        out = REPORTS_DIR / "real_evaluation.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report["systems"], indent=2))
        print(f"Malicious pages opened silently: {report['malicious_opened_silently']}")
        print(f"Benign pages interrupted: {report['benign_interrupted']}")
        print(f"Saved {out}")
        return

    n_benign, n_malicious = (1200, 800) if args.quick else (3000, 2000)
    report = run_evaluation(default_config(), seed=args.seed, n_benign=n_benign,
                            n_malicious=n_malicious, leave_one_out=not args.quick)
    path = write_report(report, REPORTS_DIR)
    print()
    print(f"{'system':20s} {'recall':>8s} {'FPR':>8s} {'precision':>10s} {'F1':>6s}")
    for name, m in report["systems"].items():
        print(f"{name:20s} {m['recall']:8.3f} {m['false_positive_rate']:8.3f} "
              f"{m['precision']:10.3f} {m['f1']:6.3f}")
    print(f"\nReport written to {path}")


if __name__ == "__main__":
    main()
