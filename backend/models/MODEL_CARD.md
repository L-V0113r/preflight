# PreFlight model card

- **Algorithm:** gradient_boosting (calibrated) (scikit-learn 1.9.1)
- **Trained:** 2026-10-17T15:03:57+00:00
- **Training data:** 6600 labelled synthetic pages (seed 7)
- **Samples:** 6600 (2600 malicious)
- **Cross-validated average precision:** logistic_regression 0.9951, gradient_boosting 0.9967

## Intended use
A second opinion, alongside rule checks, on whether a web page attacks its visitor.
It runs locally and never sends the URL anywhere.

## Not intended for
Judging whether a site is honest, legal or good value; scanning sites you don't
intend to visit; any decision about a person.

## Known limits
- Trained on synthetic pages unless real data was added (see above). Real-world
  accuracy is unmeasured until it is evaluated on real, labelled pages.
- Reads code statically, so heavily obfuscated or server-side cloaked attacks can be missed.
- Unusual pages are flagged as 'unsure' using the feature ranges stored in the model.
