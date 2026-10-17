/**
 * PreFlight overlay: the "checking..." screen and the warning pop-up.
 *
 * Drawn inside a CLOSED shadow root so that:
 *  - the page's CSS cannot restyle or hide our warning, and
 *  - the page's scripts cannot read or click our buttons.
 *
 * All text from the scanner is inserted with textContent, never innerHTML,
 * because finding evidence can contain text copied from a malicious page.
 *
 * Exposes globalThis.PreFlightOverlay for interceptor.js (same isolated world).
 */
(() => {
  'use strict';

  const VERDICT_STYLE = {
    danger: { label: 'Dangerous page', tone: 'danger', icon: '⛔' },
    caution: { label: 'This page looks risky', tone: 'caution', icon: '⚠️' },
    unsure: { label: "PreFlight couldn't confirm this page is safe", tone: 'unsure', icon: '❔' },
    error: { label: "PreFlight couldn't check this link", tone: 'unsure', icon: '❔' },
    safe: { label: 'No problems found', tone: 'safe', icon: '✓' },
  };

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .backdrop {
      position: fixed; inset: 0; z-index: 2147483647;
      background: rgba(15, 18, 25, 0.55); backdrop-filter: blur(2px);
      display: flex; align-items: center; justify-content: center; padding: 16px;
    }
    .card {
      width: min(560px, 100%); max-height: calc(100vh - 32px); overflow: auto;
      background: #ffffff; color: #1d2433; border-radius: 14px;
      box-shadow: 0 24px 60px rgba(0,0,0,.35); border-top: 6px solid var(--tone);
      --tone: #4b5565;
    }
    .card.danger { --tone: #c4320a; } .card.caution { --tone: #dc8a00; }
    .card.unsure { --tone: #5b5bd6; } .card.safe { --tone: #15803d; }
    header { padding: 20px 22px 8px; display: flex; gap: 12px; align-items: flex-start; }
    .icon { font-size: 26px; line-height: 1; }
    h1 { font-size: 19px; margin: 0 0 4px; color: var(--tone); }
    .host { font-size: 14px; color: #4b5565; word-break: break-all; }
    .body { padding: 4px 22px 8px; font-size: 14px; line-height: 1.45; }
    .finding { border: 1px solid #e3e6ec; border-radius: 10px; padding: 10px 12px; margin: 10px 0; }
    .finding h2 { font-size: 14px; margin: 0 0 4px; display: flex; gap: 8px; align-items: center; }
    .finding p { margin: 0; color: #364152; }
    .evidence { margin-top: 6px; font: 12px ui-monospace, Menlo, Consolas, monospace; color: #6b7385;
                background: #f5f6f8; padding: 4px 6px; border-radius: 6px; word-break: break-all; }
    .pill { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em;
            padding: 2px 7px; border-radius: 99px; background: #eef0f4; color: #364152; flex-shrink: 0; }
    .pill.critical, .pill.high { background: #fde4dc; color: #a12a07; }
    .pill.medium { background: #fdf0d3; color: #8a5300; }
    .ai { margin: 12px 0; padding: 10px 12px; background: #f3f2ff; border-radius: 10px; color: #3a3a8c; }
    .ai ul { margin: 6px 0 0; padding-left: 18px; }
    .notes { margin: 10px 0; padding-left: 18px; color: #4b5565; }
    details { margin: 10px 0; color: #4b5565; font-size: 13px; }
    details li { word-break: break-all; }
    footer { padding: 12px 22px 18px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }
    button { font-size: 14px; font-weight: 600; border-radius: 9px; padding: 10px 16px; cursor: pointer;
             border: 1px solid #c9ced8; background: #fff; color: #1d2433; }
    button.primary { background: #1d2433; color: #fff; border-color: #1d2433; }
    /* "Report this site" sits apart from the two navigation choices. */
    button.ghost { margin-right: auto; font-weight: 500; color: #4b5565; }
    button[disabled] { opacity: .65; cursor: default; }
    button:focus-visible { outline: 3px solid #7aa7ff; outline-offset: 2px; }
    .provenance { padding: 0 22px 16px; font-size: 11.5px; color: #6b7385; }
    .spinner { width: 22px; height: 22px; border-radius: 50%; border: 3px solid #d9dce3;
               border-top-color: #1d2433; animation: spin 0.8s linear infinite; flex-shrink: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .scanning { display: flex; gap: 14px; align-items: center; padding: 20px 22px; }
    @media (prefers-color-scheme: dark) {
      .card { background: #171b24; color: #e6e9ef; }
      .host, .notes, details, .provenance { color: #a6adbb; }
      .finding { border-color: #2c3342; } .finding p { color: #c9ceda; }
      .evidence { background: #222836; color: #a6adbb; }
      .pill { background: #2c3342; color: #d5d9e2; }
      .ai { background: #24234a; color: #c9c8ff; }
      button { background: #222836; color: #e6e9ef; border-color: #3a4254; }
      button.primary { background: #e6e9ef; color: #171b24; border-color: #e6e9ef; }
      button.ghost { color: #a6adbb; }
    }
  `;

  let host = null;
  let root = null;
  let keyHandler = null;

  /** Tiny DOM helper: el('div', {class: 'x'}, 'text', childNode) */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'class') node.className = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function mount() {
    if (host && host.isConnected) return;
    host = document.createElement('preflight-overlay');
    host.setAttribute('style', 'all: initial !important; position: fixed !important; z-index: 2147483647 !important;');
    root = host.attachShadow({ mode: 'closed' });
    root.append(el('style', {}, CSS));
    (document.documentElement || document).append(host);
  }

  function render(content) {
    mount();
    // Keep the <style>, replace everything else.
    while (root.childNodes.length > 1) root.lastChild.remove();
    root.append(content);
  }

  function hide() {
    if (keyHandler) {
      window.removeEventListener('keydown', keyHandler, true);
      keyHandler = null;
    }
    if (host) host.remove();
    host = null;
    root = null;
  }

  function onEscape(callback) {
    keyHandler = (event) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        callback();
      }
    };
    window.addEventListener('keydown', keyHandler, true);
  }

  function showScanning(hostname, onCancel) {
    const cancel = el('button', { onclick: onCancel }, 'Cancel');
    render(el('div', { class: 'backdrop' },
      el('div', { class: 'card', role: 'dialog', 'aria-live': 'polite', 'aria-label': 'PreFlight is checking this link' },
        el('div', { class: 'scanning' },
          el('div', { class: 'spinner' }),
          el('div', {},
            el('strong', {}, 'Checking this link before it opens…'),
            el('div', { class: 'host' }, hostname))),
        el('footer', {}, cancel))));
    onEscape(onCancel);
    cancel.focus();
  }

  function provenanceText(info) {
    if (!info) return '';
    const parts = [];
    if (info.algorithm) {
      const date = info.trained_at ? info.trained_at.slice(0, 10) : 'unknown date';
      parts.push(`AI model trained ${date} on ${info.training_data || 'unknown data'}`);
    } else {
      parts.push('AI model not loaded (rule checks only)');
    }
    parts.push(info.threat_list_age_days === null || info.threat_list_age_days === undefined
      ? 'threat feeds not downloaded'
      : `threat list ${info.threat_list_age_days} days old`);
    return parts.join(' · ');
  }

  /**
   * Show a scan result and let the user decide.
   * @param {object} result  ScanResult from the scanner
   * @param {{onBack: Function, onProceed: Function, onReport?: Function,
   *          onIgnore?: Function}} actions
   *   onReport ("Report this site") and onIgnore ("Ignore") are optional user-
   *   feedback hooks, both defined in lib/report_action.js, not here. onIgnore
   *   runs first and then the page opens via onProceed.
   */
  function showResult(result, { onBack, onProceed, onReport, onIgnore }) {
    const style = VERDICT_STYLE[result.verdict] || VERDICT_STYLE.unsure;
    const hostname = (() => { try { return new URL(result.url).hostname; } catch { return result.url; } })();

    const findings = (result.findings || []).filter((f) => f.severity !== 'info').map((f) =>
      el('div', { class: 'finding' },
        el('h2', {}, el('span', { class: `pill ${f.severity}` }, f.severity), f.title),
        el('p', {}, f.explanation),
        f.evidence ? el('div', { class: 'evidence' }, f.evidence) : null));

    const factors = result.ml_factors || [];
    const aiBox = (result.ml_probability !== null && result.ml_probability !== undefined)
      ? el('div', { class: 'ai' },
        `The AI model rates this page ${Math.round(result.ml_probability * 100)}% likely to be malicious.`,
        factors.length
          ? el('ul', {}, ...factors.map((f) => el('li', {}, `It noticed ${f.description}.`)))
          : null)
      : null;

    const notes = (result.notes || []).length
      ? el('ul', { class: 'notes' }, ...result.notes.map((n) => el('li', {}, n)))
      : null;

    const chain = result.redirect_chain || [];
    const redirects = chain.length > 1
      ? el('details', {}, el('summary', {}, `This link redirects ${chain.length - 1} time(s)`),
        el('ol', {}, ...chain.map((u) => el('li', {}, u))))
      : null;

    const dangerous = result.verdict === 'danger';
    const back = el('button', { class: 'primary', onclick: onBack }, 'Go back (recommended)');

    // "Ignore": the user says the site is fine. Record that (onIgnore, defined
    // in lib/report_action.js) and then open the page via onProceed. If no
    // onIgnore hook is given it just opens the page, like the old button did.
    const ignore = el('button', {
      onclick: async () => {
        try {
          if (onIgnore) await onIgnore();
        } catch { /* feedback is best-effort; still open the page */ }
        onProceed();
      },
    }, dangerous ? 'Ignore warning, open anyway' : 'Ignore, open the page');

    // "Report this site": the user says the site is bad. This never navigates
    // and never changes the verdict. It hands the details to onSiteReported()
    // in lib/report_action.js and shows whatever that returns.
    const report = onReport ? el('button', { class: 'ghost' }, 'Report this site') : null;
    if (report) {
      report.addEventListener('click', async () => {
        report.disabled = true;
        report.textContent = 'Reporting…';
        let message = 'Reported';
        try {
          const outcome = await onReport();
          if (outcome && outcome.message) message = outcome.message;
        } catch {
          message = "Couldn't record that";
        }
        report.textContent = message;
      });
    }

    render(el('div', { class: 'backdrop' },
      el('div', { class: `card ${style.tone}`, role: 'alertdialog', 'aria-modal': 'true', 'aria-label': style.label },
        el('header', {},
          el('div', { class: 'icon', 'aria-hidden': 'true' }, style.icon),
          el('div', {}, el('h1', {}, style.label), el('div', { class: 'host' }, hostname))),
        el('div', { class: 'body' }, ...findings, aiBox, notes, redirects),
        el('footer', {}, report, ignore, back),
        el('div', { class: 'provenance' }, provenanceText(result.model_info)))));
    onEscape(onBack);
    back.focus();
  }

  /** Show a problem with PreFlight itself (scanner off, wrong token...). */
  function showError(message, { onBack, onProceed }) {
    const back = el('button', { class: 'primary', onclick: onBack }, 'Go back');
    const proceed = onProceed ? el('button', { onclick: onProceed }, 'Open without checking') : null;
    render(el('div', { class: 'backdrop' },
      el('div', { class: 'card unsure', role: 'alertdialog', 'aria-modal': 'true' },
        el('header', {},
          el('div', { class: 'icon', 'aria-hidden': 'true' }, '❔'),
          el('div', {}, el('h1', {}, "PreFlight couldn't check this link"),
            el('div', { class: 'host' }, message))),
        el('footer', {}, proceed, back))));
    onEscape(onBack);
    back.focus();
  }

  // Coming back to a page from the back/forward cache: never show a stale overlay.
  window.addEventListener('pageshow', (event) => { if (event.persisted) hide(); });

  globalThis.PreFlightOverlay = Object.freeze({ showScanning, showResult, showError, hide });
})();
