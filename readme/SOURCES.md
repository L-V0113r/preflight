# Sources used during development

Every source that informed PreFlight, with what it was used for. "Accessed" is the date it was consulted. **How used** says whether the page was read in full, seen only as a search-result title and snippet, or is background knowledge (from the AI assistant's training, not opened during this session). Background-knowledge entries are listed so nothing is hidden, and you should verify them yourself before relying on them.

## Research and threat intelligence

| # | Source | Publisher / author | URL | Used for | How used | Accessed |
|---|---|---|---|---|---|---|
| 1 | How ClickFix is weaponizing verification fatigue to deliver RATs & infostealers | SentinelOne | https://www.sentinelone.com/de/blog/how-clickfix-is-weaponizing-verification-fatigue-to-deliver-rats-infostealers/ | How ClickFix pages put commands on the clipboard (clipboard copy, PowerShell `-w h`, `iex`, mshta, certutil) and guide users to the Run dialog → `js.clipboard_command`, `LOLBIN` pattern, ClickFix synthetic family | Read | 17 Oct 2026 |
| 2 | ClickFix Captcha: a creative technique that allows attackers to deliver malware | Cyber Security News | https://cybersecuritynews.com/clickfix-captcha-a-creative-technique | Confirming ClickFix is a current, widespread technique | Search result | 17 Oct 2026 |
| 3 | Understanding the ClickFix attack | Doctor Web | https://news.drweb.com/show/?i=15074 | As above | Search result | 17 Oct 2026 |
| 4 | Fake Cloudflare CAPTCHA page laden with malware uncovered | TechRadar | https://www.techradar.com/pro/security/fake-cloudflare-captcha-page-laden-with-malware-uncovered-in-the-wild-heres-how-to-stay-secure-and-safe | Fake-CAPTCHA page styling ("Just a moment...") in samples | Search result | 17 Oct 2026 |
| 5 | OWASP Top 10 Client-Side Security Risks | OWASP Foundation | https://owasp.org/www-project-top-10-client-side-security-risks/ | Client-side risk categories: third-party script control, sensitive data leakage, JavaScript drift → third-party script features, skimmer rules | Read | 17 Oct 2026 |
| 6 | T1189 Drive-by Compromise | MITRE ATT&CK | https://attack.mitre.org/techniques/T1189 | Drive-by methods: injected JS, hidden iframes, malvertising, push-notification abuse → hidden-iframe, auto-download, malvertising, push-bait rules | Read | 17 Oct 2026 |
| 7 | Browser-in-the-browser phishing (mr.d0x research, reported) | The Register | https://www.theregister.com/2022/03/18/browser_in_browser_phishing/ | Fake pop-up window built from HTML/CSS + iframe with spoofed URL → `html.browser_in_browser` | Read | 17 Oct 2026 |
| 8 | Web-based Cryptojacking in the Wild (arXiv:1808.09474) | TU Braunschweig, Institute for Application Security | https://ar5iv.arxiv.org/html/1808.09474 | Miner signals: WebAssembly, many workers, WebSocket pools, known script names (coinhive, CryptoLoot); limits of static block lists → `MINER` pattern, cryptojacking rule | Read | 17 Oct 2026 |
| 9 | Security scanners consuming one-time links | The Plugin People (Atlassian wiki) | https://thepluginpeople.atlassian.net/wiki/spaces/JEMHC/pages/3856236545/Security+Scanners+consuming+one+time+links | The documented limitation that pre-fetching uses up one-time links | Read | 17 Oct 2026 |
| 10 | Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation (NDSS 2019) | Le Pochat et al. | https://arxiv.org/pdf/1806.01156 | Recommended source of benign sites for building a real dataset | Search result | 17 Oct 2026 |
| 11 | "Browser-Based Deep Behavioral Detection of Web…" (title truncated in the search result) | NDSS Symposium | https://www.ndss-symposium.org/wp-content/uploads/23002-paper.pdf | Background on behavioural vs static miner detection | Search result | 17 Oct 2026 |
| 12 | Blacksite AiTM phishing kit cloaked | Abnormal AI | https://abnormal.ai/blog/blacksite-aitm-phishing-kit-cloaked-gg | Cloaking (showing scanners harmless content) → documented limitation, browser-like User-Agent | Search result | 17 Oct 2026 |
| 13 | IDN homograph attack | Punycoder | https://www.punycoder.com/idn-homograph-attack/ | Homograph / punycode look-alike domains → confusables skeleton | Search result | 17 Oct 2026 |
| 14 | What is DNS rebinding? | Vaadata | https://www.vaadata.com/en/blog/what-is-dns-rebinding-exploitations-and-security-best-practices/ | Why the fetcher pins the checked IP and the server checks the Host header | Search result | 17 Oct 2026 |

## Threat feeds (data)

| # | Source | URL | Used for | Licence / terms | Accessed |
|---|---|---|---|---|---|
| 15 | OpenPhish community feed (`feed.txt`, updated about every 12 h) | https://github.com/openphish/public_feed | Optional offline block list (`update_threat_feeds.py`) | **Non-commercial use only**, OpenPhish Terms of Use (https://openphish.com/terms.html, not reviewed here) | Read 17 Oct 2026. Not downloaded during development (sandbox network blocked) |
| 16 | URLhaus by abuse.ch | https://urlhaus.abuse.ch/api/ | Optional malware-URL block list. Needs a free Auth-Key. Export URL pattern taken from this page | Free under fair use. Commercial use may need a paid plan (abuse.ch terms) | Read 17 Oct 2026. Not downloaded during development |
| 17 | Labelled synthetic web pages | `backend/preflight/data/synthetic.py` (this project) | All model training and evaluation | Generated by this project, same licence as the code | Generated 17 Oct 2026 (seed 7 for training, 11 for evaluation) |
| 18 | Hand-written sample pages | `backend/samples/` (this project) | Demo and end-to-end tests | Generated by this project. Inert. Fictional brand "Northbridge Bank" on the reserved `.example` domain | Written 17 Oct 2026 |

No real user data, browsing history or customer data was used.

## Platform and library documentation

| # | Source | URL | Used for | How used | Accessed |
|---|---|---|---|---|---|
| 19 | Chrome Extensions: Content scripts | https://developer.chrome.com/docs/extensions/mv3/content_scripts | Isolated worlds, `run_at: document_start`, `all_frames` | Read | 17 Oct 2026 |
| 20 | Chrome Extensions: Message passing | https://developer.chrome.com/docs/extensions/develop/concepts/messaging | `runtime.sendMessage`, returning `true` to keep `sendResponse` open | Read | 17 Oct 2026 |
| 21 | scikit-learn `CalibratedClassifierCV` | https://scikit-learn.org/1.7/modules/generated/sklearn.calibration.CalibratedClassifierCV.html | Probability calibration (isotonic / sigmoid) | Search result + background knowledge | 17 Oct 2026 |
| 22 | scikit-learn user guide (HistGradientBoostingClassifier, LogisticRegression, StratifiedKFold, metrics) | https://scikit-learn.org/stable/ | Model training and evaluation API | Background knowledge | — |
| 23 | Python standard library docs: `html.parser`, `http.client`, `ssl`, `socket`, `ipaddress`, `zlib`, `http.server`, `hmac`, `secrets` | https://docs.python.org/3/library/ | Fetcher, parser, server, token handling | Background knowledge | — |
| 24 | Chrome Extensions: Manifest V3, `chrome.storage`, `chrome.tabs`, options pages | https://developer.chrome.com/docs/extensions/ | Extension structure | Background knowledge | — |
| 25 | MDN Web Docs: Shadow DOM, `AbortController`, `Node.textContent` | https://developer.mozilla.org/ | Closed shadow root UI, request timeouts, XSS-safe text insertion | Background knowledge | — |

## Concepts and further reading (background knowledge)

| # | Source | URL | Used for |
|---|---|---|---|
| 26 | Unicode Technical Standard #39: Unicode Security Mechanisms (confusables) | https://www.unicode.org/reports/tr39/ | Basis of the look-alike character map |
| 27 | Public Suffix List | https://publicsuffix.org/ | "Registrable domain" concept; PreFlight ships a small approximation |
| 28 | OWASP SSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html | Address-guard design |
| 29 | Shannon, C. E. (1948). A Mathematical Theory of Communication | https://doi.org/10.1002/j.1538-7305.1948.tb01338.x | Entropy feature |
| 30 | Levenshtein, V. I. (1966). Binary codes capable of correcting deletions, insertions, and reversals | — | Edit distance for typo-squatting |
| 31 | Niculescu-Mizil, A. & Caruana, R. (2005). Predicting good probabilities with supervised learning (ICML) | https://doi.org/10.1145/1102351.1102430 | Why boosted trees need calibration |
| 32 | Zadrozny, B. & Elkan, C. (2002). Transforming classifier scores into accurate multiclass probability estimates (KDD) | https://doi.org/10.1145/775047.775151 | Isotonic calibration |
| 33 | Lundberg, S. & Lee, S.-I. (2017). A Unified Approach to Interpreting Model Predictions (SHAP) | https://arxiv.org/abs/1705.07874 | Suggested upgrade from occlusion attribution |
| 34 | Geirhos, R. et al. (2020). Shortcut learning in deep neural networks | https://arxiv.org/abs/2004.07780 | The "shortcut learning" idea in `06_synthetic_data_and_shortcuts.md` |
| 35 | Mitchell, M. et al. (2019). Model Cards for Model Reporting | https://arxiv.org/abs/1810.03993 | `models/MODEL_CARD.md` format |

## Event material

| # | Source | Used for |
|---|---|---|
| 36 | SotonShip 2026 track briefs: FinTech, Responsible AI, Southampton City (PDFs supplied by the team) | Requirements: baseline comparison, labelled synthetic data, failure demo, README disclosures, data-source table |
