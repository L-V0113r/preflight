# PreFlight — check a page before it opens

PreFlight is a small AI that runs **on your own computer** next to your browser. When you click a link to another website, PreFlight downloads the page **without running any of it**, checks it for attacks on the visitor, and only then lets it open. If something looks wrong, a pop-up explains what it found **before** the page loads, and you decide.

It is built for people who value privacy and would rather wait a moment than take a risk. The URLs you visit are never sent to any cloud service. The model, the rules and the threat lists all live on your machine.

> **One-sentence pitch:** We help privacy-conscious people avoid phishing, scam and malware pages by checking every link on their own computer, with an explainable AI, before the page can load.

---

## What it catches

| Attack on the visitor | How PreFlight spots it |
|---|---|
| **Phishing / fake login pages** | password forms that send to another site, look-alike domains (`paypa1.com`, Cyrillic look-alikes), brand names in someone else's link, a page claiming to be a brand it isn't hosted by, pressure language |
| **"ClickFix" fake CAPTCHAs** | code that silently copies a PowerShell/mshta command to your clipboard, plus "press Windows + R, then Ctrl + V" instructions |
| **Card skimmers (Magecart-style)** | checkout pages whose scripts read form fields and beam them to another site |
| **Keyloggers** | scripts that record typing and send it off-site |
| **Drive-by downloads / fake updates** | hidden cross-site frames, automatic redirects to program files, "your browser is out of date" + `.exe` |
| **Browser-in-the-browser** | a fake sign-in "window" drawn inside the page with a fake address bar |
| **Cryptojacking** | known browser-miner code, WebAssembly/worker mining patterns |
| **Tech-support scams** | fake virus alerts with phone numbers, full-screen and endless-alert lock-ins |
| **Notification spam bait** | "Click Allow to prove you're not a robot" + permission requests |
| **Malvertising chains** | links that bounce through several unrelated sites |
| **Known bad sites** | offline lookup in downloaded threat feeds (OpenPhish, optional URLhaus) |

A machine-learning model scores every page as well, so pages that resemble these attacks without matching a rule exactly still raise a warning.

## How it works

```
 you click a link
        │
        ▼
 ┌───────────────────────┐   message   ┌────────────────────┐   HTTP + token   ┌──────────────────────────────┐
 │ content script        │ ──────────▶ │ extension service  │ ───────────────▶ │ local scanner (Python)       │
 │ (stops the navigation │             │ worker (holds the  │                  │ 127.0.0.1:8765               │
 │  and shows "checking")│ ◀────────── │ secret token)      │ ◀─────────────── │                              │
 └───────────────────────┘   verdict   └────────────────────┘    ScanResult    │ 1 safe fetch (no JS, no      │
        │                                                                      │   cookies, SSRF-guarded)     │
        ▼                                                                      │ 2 parse HTML, read scripts   │
 safe   → page opens, no interruption                                          │ 3 rules for known attacks    │
 unsure → pop-up explains why it couldn't confirm                              │ 4 offline threat-list lookup │
 caution/danger → warning pop-up, "Go back" is the default                     │ 5 AI model + explanation     │
                                                                               │ 6 combine → verdict          │
                                                                               └──────────────────────────────┘
```

The verdict combines three kinds of evidence. **Rules** give precise, explainable answers for known attack classes. The **AI model** (a calibrated gradient-boosted tree ensemble over 74 engineered features) covers the grey areas. **Threat feeds** catch known-bad sites. When PreFlight couldn't read the page, or the model is unsure, or the page is unlike anything it was trained on, it answers **Unsure** rather than pretending a page is safe. Details are in [`readme/ai_techniques`](ai_techniques/).

## Quick start

You need Python 3.10+ and Google Chrome (or another Chromium browser: Edge, Brave).

```bash
# 1. Install (inside the backend folder)
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Train the model (about 30 seconds) and check everything works
python train_model.py
python -m unittest                 # 50+ tests, a few seconds

# 3. Optional: download threat feeds (repeat daily)
python update_threat_feeds.py

# 4. Start the scanner. It prints a secret token the first time.
python run_server.py
```

Then load the extension:

1. Open `chrome://extensions`, switch on **Developer mode**.
2. Click **Load unpacked** and choose the `extension` folder.
3. The settings page opens. Paste the token from step 4 and press **Test connection**.

Now click any link to another site. Safe pages open after a short check. Risky ones show the PreFlight pop-up.

### Try it safely with the demo pages

```bash
cd backend
python serve_demo.py                         # terminal 1: serves inert sample pages
python run_server.py --allow-private-targets # terminal 2: demo mode lets the scanner reach localhost
```

Open <http://127.0.0.1:8000/> and click the links. There are 3 honest pages and 8 attack pages, plus two failure cases: an unreachable site (→ Unsure, with an explanation) and a block-listed domain (→ Danger, even though the page can't be loaded). Every sample is synthetic and inert. Attacker domains use the reserved `.invalid` ending, so nothing can ever load, and commands only print a test message.

### Use it from the terminal

```bash
python scan_cli.py https://example.com
python scan_cli.py https://example.com --json
python scan_cli.py --file samples/malicious_clickfix_captcha.html --as-url https://verify.example/
```

## Settings (extension options page)

| Setting | Default | Meaning |
|---|---|---|
| How thorough | Full check | *Link only* never downloads the page: faster and more private, but much less accurate |
| If the scanner isn't running | Ask me | or *Block the link*, or *Open without checking* |
| Maximum wait | 20 s | after this the scan is abandoned and treated as "couldn't check" |

## Privacy and safety design

- **Local only.** The server listens on `127.0.0.1` only. The extension refuses any scanner address other than `127.0.0.1`.
- **No code is run.** Pages are read as text. JavaScript is analysed statically, never executed.
- **The scanner can't be abused by websites.** It requires a secret token, rejects web-page origins, checks the `Host` header (blocks DNS rebinding), and refuses to fetch private or local addresses (blocks SSRF), pinning each connection to the IP it checked.
- **No cookies are sent** when fetching, so the site doesn't learn who you are, only that someone at your IP asked for the page.
- **Quiet logs.** URLs are not logged unless you start the server with `--verbose`.
- **Threat feeds are downloaded, not queried**, so your browsing isn't sent to a reputation service.
- **You stay in control.** Every warning has an "open anyway" option. That choice is remembered only until the browser closes.

## Limitations (please read)

- **The model has only been tested on synthetic data.** It was trained and evaluated on labelled synthetic pages (see [`readme/ai_techniques/06_synthetic_data_and_shortcuts.md`](readme/ai_techniques/06_synthetic_data_and_shortcuts.md)). The synthetic evaluation is in [`backend/reports/evaluation_report.md`](backend/reports/evaluation_report.md). Real-world accuracy is **unmeasured** until you run `python evaluate.py --real-dir <folder>` on real labelled pages.
- **The scanner downloads the page, and that has side effects.** The site sees one extra request from your IP. One-time links (password resets, "magic" login links, unsubscribe links) can be **used up** by the scan, the same problem email link-scanners cause. Use *Link only* mode, or "open anyway", for those.
- **Cloaking.** Some attack kits show harmless content to anything that isn't a real browser. PreFlight looks like a normal Chrome request but doesn't run JavaScript, so it can be shown a decoy.
- **Static analysis can be evaded** by heavy obfuscation or code fetched at run time. Obfuscation itself is treated as a warning sign.
- **Not everything is intercepted.** Ctrl/Cmd/middle-click (new tab), typed URLs, bookmarks, links to the same host, and navigation started by a page's own scripts are not scanned in this version.
- **Look-alike detection needs a list.** It only knows the brands in `backend/threat_data/protected_domains.txt`. Add the banks and services you use.
- **Speed.** Analysis takes tens of milliseconds. Downloading the page adds normal network time, typically 0.3–3 s.
- **Honest sites can trip rules.** Company single sign-on and identity providers not in the allow-list, sites with many hidden tracking frames, and old sites that use `eval` can all do this. That's why every warning explains itself and can be overridden.

## Project structure

```
preflight/
├── README.md                    → pointer to this folder
├── readme/                      → all documentation (you are here)
├── extension/                   Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js            service worker: talks to the scanner
│   ├── lib/                     settings.js, api_client.js, session_state.js (ES modules)
│   ├── content/                 overlay.js (pop-up UI), interceptor.js (catches clicks)
│   └── options/                 settings page
└── backend/                     Python scanner
    ├── run_server.py            start the local API
    ├── scan_cli.py              scan from the terminal / collect pages
    ├── train_model.py           train + save the model and model card
    ├── evaluate.py              synthetic study, or --real-dir for real pages
    ├── update_threat_feeds.py   download OpenPhish / URLhaus lists
    ├── serve_demo.py            local demo site
    ├── preflight/               the package (each folder is a small library)
    │   ├── schema.py config.py context.py scoring.py scanner.py server.py auth.py cache.py
    │   ├── net/                 address_guard.py (SSRF), safe_fetcher.py
    │   ├── parsing/             url_tools.py, html_parser.py
    │   ├── features/            script_analysis.py, text_analysis.py, url/page features, vectoriser.py
    │   ├── detectors/           url, transport, form, script, content rules + threat_intel.py
    │   ├── ml/                  model.py, trainer.py, dataset.py, evaluation.py, report.py
    │   └── data/                synthetic.py (labelled generator), loaders.py (real data)
    ├── samples/                 11 inert labelled sample pages
    ├── threat_data/             protected brands, your block lists, downloaded feeds
    ├── models/                  trained model + MODEL_CARD.md
    ├── reports/                 evaluation_report.md / .json
    └── tests/                   unittest suite (unit + end-to-end)
```

## For the SotonShip judges

- **User.** Privacy-conscious individuals who would rather wait a second than be phished: people who bank and shop online, and people who've been scammed before.
- **Problem evidence.** The attack classes come from public threat research: MITRE ATT&CK T1189 (drive-by compromise), the OWASP client-side risks project, ClickFix reporting, and browser-in-the-browser research. See [`readme/SOURCES.md`](readme/SOURCES.md).
- **AI at the core.** The model is compared against a keyword baseline and against the rules alone (see the evaluation report). It also explains itself (occlusion attribution) and knows when it's out of its depth (out-of-distribution check).
- **Responsibility.** Local-only processing, an SSRF-safe fetcher, override always available, an "Unsure" verdict instead of false reassurance, model card, honest failure demo.
- **Business model to test.** The ideas below are hypotheses, not validated.
  - A free personal version, plus a paid tier for families or small offices with managed protected-brand lists.
  - Licensing to banks and wallet providers, who could ship it to customers to cut reimbursed scam losses. Their protected list would be their own domains.
  - Running cost is almost nothing per user, because all inference runs on the user's CPU. There are no per-request AI fees.
- **Second market.** Swap in that country's banks in `protected_domains.txt`. Add its public suffixes to `url_tools.py`. Add local scam phrases to `text_analysis.py`.

## AI use, prior work and help (hackathon rule)

The whole codebase and these documents were generated by **Claude (Anthropic), an AI assistant**, on 17 October 2026, during the event. The work followed the team's specification. Nothing existed before the event, and no outside help was used. Full disclosure is in [`readme/DEVELOPMENT.md`](readme/DEVELOPMENT.md). All data sources, with dates and licences, are listed in [`readme/SOURCES.md`](readme/SOURCES.md).
