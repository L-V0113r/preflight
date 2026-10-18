/**
 * PreFlight click interceptor.
 *
 * Runs in every page (isolated world, at document_start). When you click a
 * link to a DIFFERENT host, it stops the navigation, asks the background
 * worker to scan the target, and then either continues silently (safe) or
 * shows the PreFlight pop-up and lets you decide.
 *
 * Ctrl/Cmd-clicks and middle-clicks (new tab) and Shift-clicks (new window)
 * are checked too, then opened the way the user asked.
 *
 * Not intercepted (see readme/README.md "Limitations"):
 *  - links to the same host you're already on;
 *  - Alt-clicks (download shortcut) and the right-click menu;
 *  - navigation done by the page's own scripts, typed URLs and bookmarks.
 */
(() => {
  'use strict';

  const overlay = globalThis.PreFlightOverlay;
  if (!overlay || window.top !== window) return;

  let busy = false;
  let bypassHref = null; // lets our own re-click of a download link through

  // Capture phase: run before the page's own handlers.
  window.addEventListener('click', onClick, true);
  window.addEventListener('auxclick', onClick, true); // middle button

  function findLink(event) {
    for (const node of event.composedPath()) {
      if ((node instanceof HTMLAnchorElement || node instanceof HTMLAreaElement) && node.href) {
        return node;
      }
    }
    return null;
  }

  /**
   * How the browser would have opened this click:
   * 'same' (this tab), 'background' (new tab behind), 'foreground'
   * (new tab in front), 'window' (new window), or null if not handled.
   */
  function openMode(event) {
    if (event.altKey) return null;
    const newTabKey = event.ctrlKey || event.metaKey;
    if (event.type === 'auxclick') {
      if (event.button !== 1) return null;
      return event.shiftKey ? 'foreground' : 'background';
    }
    if (event.button !== 0) return null;
    if (newTabKey) return event.shiftKey ? 'foreground' : 'background';
    if (event.shiftKey) return 'window';
    return 'same';
  }

  function shouldScan(event, link) {
    if (!openMode(event)) return null;
    let url;
    try {
      url = new URL(link.href, document.baseURI);
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.hostname === location.hostname) return null;
    if (bypassHref === url.href) {
      bypassHref = null;
      return null;
    }
    return url;
  }

  function onClick(event) {
    const link = findLink(event);
    if (!link) return;
    const url = shouldScan(event, link);
    if (!url) return;
    const mode = openMode(event);

    // Stop the browser (and the page's own click handlers) from navigating.
    event.preventDefault();
    event.stopImmediatePropagation();
    if (busy) return;
    checkThenNavigate(link, url, mode);
  }

  /** Carry out the navigation the user originally asked for. */
  function navigate(link, url, mode) {
    overlay.hide();
    if (mode !== 'same') {
      chrome.runtime.sendMessage({ type: 'preflight:open-tab', url: url.href, mode });
      return;
    }
    const baseTarget = document.querySelector('base[target]')?.getAttribute('target') || '';
    const target = (link.getAttribute('target') || baseTarget).toLowerCase();
    if (link.hasAttribute('download')) {
      bypassHref = url.href;
      link.click(); // keeps the browser's download behaviour
    } else if (target && !['_self', '_top', '_parent'].includes(target)) {
      chrome.runtime.sendMessage({ type: 'preflight:open-tab', url: url.href, mode: 'foreground' });
    } else {
      window.location.assign(url.href);
    }
  }

  async function checkThenNavigate(link, url, mode) {
    busy = true;
    let cancelled = false;
    overlay.showScanning(url.hostname, () => {
      cancelled = true;
      busy = false;
      overlay.hide();
    });

    let response;
    try {
      response = await chrome.runtime.sendMessage({ type: 'preflight:scan', url: url.href });
    } catch {
      response = {
        status: 'error',
        message: 'PreFlight was updated or restarted. Reload this page and try again.',
        failMode: 'ask',
      };
    }
    busy = false;
    if (cancelled) return;

    const goBack = () => overlay.hide();
    const goAnyway = () => navigate(link, url, mode);

    if (!response || response.status === 'allowed') {
      navigate(link, url, mode);
      return;
    }

    if (response.status === 'error') {
      if (response.failMode === 'open') {
        navigate(link, url, mode);
      } else {
        overlay.showError(response.message, {
          onBack: goBack,
          onProceed: response.failMode === 'block' ? null : goAnyway,
        });
      }
      return;
    }

    const result = response.result;
    if (result.verdict === 'safe') {
      navigate(link, url, mode); // safe pages open with no interruption
      return;
    }

    overlay.showResult(result, {
      onBack: goBack,
      // Report / Ignore are handled in background.js -> lib/report_action.js.
      onReport: () => chrome.runtime.sendMessage({
        type: 'preflight:report-site',
        url: url.href,
        verdict: result.verdict,
        riskScore: result.risk_score,
      }),
      onIgnore: () => chrome.runtime.sendMessage({
        type: 'preflight:ignore-site',
        url: url.href,
        verdict: result.verdict,
        riskScore: result.risk_score,
      }),
      onProceed: async () => {
        // Remember the choice for this site until the browser is closed.
        await chrome.runtime.sendMessage({ type: 'preflight:allow-site', hostname: url.hostname });
        navigate(link, url, mode);
      },
    });
  }
})();
