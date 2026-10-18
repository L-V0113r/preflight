# PreFlight — check a page before it opens

## About

PreFlight is a privacy-first browser safety tool built for SotonShip 2026. It runs locally alongside a Chromium browser: when a user clicks a link, a lightweight extension asks a local Python scanner to fetch the destination (without executing JavaScript), run explainable rule-based checks plus a compact ML model, and return a verdict and human-readable explanation. PreFlight targets phishing, scam, skimming, cryptojacking and related client-side threats while keeping all URLs and scans on the user's device.

License: MIT (SPDX: MIT)

> One-sentence pitch: We help privacy-conscious people avoid phishing, scam and malware pages by checking every link on their own computer, with an explainable AI, before the page can load.

---

## How to run it

You need **Python 3.10 or newer** and **Google Chrome** (or another Chromium browser: Edge, Brave). On Windows, tick *"Add python.exe to PATH"* when installing Python.

### Windows: the easy way

1. Double-click **`Start PreFlight.bat`** in the project folder. The first time, it sets everything up (about a minute): it creates `backend\.venv`, installs the libraries, trains the model and runs the self-tests. **Leave the window open** while you browse. Closing it stops PreFlight.
2. In Chrome, open `chrome://extensions` and switch on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder.
4. Hover over the PreFlight icon in the toolbar (pin it from the puzzle-piece menu). It should say **PreFlight is RUNNING**. You don't need to paste a token: the scanner writes it into the extension folder and the extension picks it up by itself.

Now click any link to another site. Safe pages open after a short check. Risky ones show the PreFlight pop-up.

**Demo pages:** close the normal scanner window first, then double-click **`Start PreFlight demo.bat`**. It starts the scanner in demo mode and opens the demo page in your browser.

### Any system: from a terminal

Run these from the project folder. On Windows, use `.venv\Scripts\python.exe` wherever you see `.venv/bin/python`.

```bash
cd backend
python -m venv .venv                          # Windows: py -3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python train_model.py               # trains the model, about 30 seconds
.venv/bin/python -m unittest                  # 64 self-tests, a few seconds
.venv/bin/python update_threat_feeds.py       # optional: download threat feeds (repeat daily)
.venv/bin/python run_server.py                # start the scanner; leave it running (Ctrl+C stops it)
```

Then load the extension in Chrome as in steps 2–4 above.

### Try it safely with the demo pages

Stop the normal scanner first (Ctrl+C), because both use the same port. Then open **two terminals** in the `backend` folder:

```bash
# Terminal 1: serves the inert sample pages
.venv/bin/python serve_demo.py

# Terminal 2: the scanner in demo mode, which may check pages on this computer
.venv/bin/python run_server.py --allow-private-targets
```

Open <http://127.0.0.1:8000/> and click the links: 3 honest pages and 8 attack pages, plus two failure cases. One is an unreachable site (→ Unsure, or Safe in Balanced mode if the link looks clean) and one is a block-listed domain (→ Danger, even though the page can't be loaded). Ctrl-click or middle-click a link to check that new-tab clicks are scanned too. Every sample is synthetic and inert. Attacker domains use the reserved `.invalid` ending, so nothing can ever load, and commands only print a test message.

### Use it from the terminal

```bash
.venv/bin/python scan_cli.py https://example.com
.venv/bin/python scan_cli.py https://example.com --json
.venv/bin/python scan_cli.py --file samples/malicious_clickfix_captcha.html --as-url https://verify.example/
```

### If it doesn't work

| What you see | What to do |
|---|---|
| Icon hover says *NOT RUNNING* | Start the scanner (`Start PreFlight.bat` or `run_server.py`) and keep its window open. |
| Icon hover says *NOT CONNECTED* | The extension has an old token. Open the PreFlight settings (click the icon), clear the token box, press **Save**, then **Test connection**. |
| "Python was not found" | Install Python 3.10+ from python.org with *Add python.exe to PATH* ticked, then run the `.bat` again. |
| Demo links open without a pop-up, or say the page couldn't be checked | Use demo mode (`--allow-private-targets`). The normal scanner refuses to check pages on your own computer. |
| You changed the code | Reload the extension on `chrome://extensions` and restart the scanner. To redo the Windows setup, delete `backend\.venv\preflight_ready.txt`. |

## Project structure

```text
preflight/
├── LICENSE
├── README.md
├── SOURCES.md
├── DEVELOPMENT.md
├── THIRD_PARTY_NOTICES.md
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content/
│   ├── lib/
│   └── options/
├── backend/
│   ├── run_server.py
│   ├── scan_cli.py
│   ├── train_model.py
│   ├── evaluate.py
│   ├── update_threat_feeds.py
│   ├── serve_demo.py
│   ├── requirements.txt
│   ├── preflight/
│   ├── samples/
│   ├── threat_data/
│   ├── models/
│   ├── reports/
│   └── tests/
└── .gitignore
```

## Documentation and provenance

- [readme/README.md](readme/README.md) — full documentation: how it works, settings, privacy design, limitations
- [readme/LEARN_TO_BUILD_IT.md](readme/LEARN_TO_BUILD_IT.md) — a guide to building it yourself, with the maths
- [SOURCES.md](SOURCES.md) — source and data provenance for the project
- [DEVELOPMENT.md](DEVELOPMENT.md) — development notes and verification steps
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — third-party and dependency license notes

## AI use, prior work and help

The codebase and documentation were generated by Claude (Anthropic) during the SotonShip event. Research sources are listed in [SOURCES.md](SOURCES.md).
