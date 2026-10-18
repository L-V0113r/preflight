# Threat data

This directory contains threat intelligence data and local generated artifacts used by PreFlight.

## Included data

- Protected brand/domain lists (if present)
- Local blocklists and allowlists
- Downloaded feed snapshots, if generated locally

## Upstream data sources

Threat feeds are downloaded by `backend/update_threat_feeds.py` and may come from sources such as:

- OpenPhish public feed: https://github.com/openphish/public_feed
- URLhaus: https://urlhaus.abuse.ch/api/

These sources have their own terms and must be checked before redistribution or commercial reuse. If you keep feed snapshots in this repo, document the source URL, access date, and upstream terms.

## Repository note

This directory is not a general-purpose data set. It is used for local scanner checks and local evaluation only.
