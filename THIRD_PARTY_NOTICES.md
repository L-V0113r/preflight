# Third-party notices

This project uses third-party software, libraries, threat feeds, and public research materials. The repository is licensed under the MIT License (see [LICENSE](../LICENSE)).

## Runtime dependencies

- numpy — BSD-3-Clause
- scikit-learn — BSD-3-Clause
- joblib — BSD-3-Clause
- Python standard library — Python Software Foundation License

## Threat feeds and data sources

The project optionally downloads threat feeds at runtime via `backend/update_threat_feeds.py`.

- OpenPhish public feed: https://github.com/openphish/public_feed
  - Terms vary; use is subject to the feed's upstream license/terms and misuse policies.
- URLhaus: https://urlhaus.abuse.ch/api/
  - Terms and fair-use conditions apply; check upstream policy before redistribution.

The project does not bundle these feeds by default. If a feed snapshot is added locally, it should be retained only under the upstream provider's terms and documented in `backend/threat_data/`.

## Public research / documentation used during development

The research and documentation sources used to build PreFlight are listed in [SOURCES.md](../SOURCES.md). Those materials remain the property of their original authors and publishers.

## Project-generated materials

Project-generated content is covered by the repository's license unless otherwise stated.

- `backend/samples/` — generated demonstration pages
- `backend/preflight/data/` — generated synthetic datasets, loaders, and evaluation input
- `backend/models/` — generated model artifacts, subject to the repo's license unless upstream licensing terms apply
- `backend/my_sites.txt` — curated safe-site allowlist generated for this project

If you redistribute generated artifacts, retain the upstream notices and the repository license.
