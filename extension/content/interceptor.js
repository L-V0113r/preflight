/**
 * PreFlight click interceptor.
 *
 * Runs in every page (isolated world, at document_start). When you click a
 * link to a DIFFERENT host, it stops the navigation, asks the background
 * worker to scan the target, and then either continues silently (safe) or
 * shows the PreFlight pop-up and lets you decide.
 *
 * Deliberately NOT intercepted (see readme/README.md "Limitations"):
 *  - links to the same host you're already on (fast, and the page was
 *    already checked when you arrived);
 *  - Ctrl/Cmd/Shift/Alt-clicks and middle-clicks (new tab/window shortcuts);
 *  - navigation done by the page's own scripts, typed URLs and bookmarks.
 */
(() => {
  'use strict';

  const overlay = globalThis.PreFlightOverlay;
  if (!overlay || window.top !== window) return;

  let busy = false;
  let bypassHref = null; // lets our own re-click of a download link through

  window.addEventListener('click', onClick, true); // capture phase: run before the page

  function findLink(event) {
    for (const node of event.composedPath()) {
      if ((node instanceof HTMLAnchorElement || node instanceof HTMLAreaElement) && node.href) {
        return node;
      }
    }
    return null;
  }

  function shouldScan(event, link) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return null;
    }
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

    // Stop the browser (and the page's own click handlers) from navigating.
    event.preventDefault();
    event.stopImmediatePropagation();
    if (busy) return;
    checkThenNavigate(link, url);
  }

  /** Carry out the navigation the user originally asked for. */
  function navigate(link, url) {
    overlay.hide();
    const baseTarget = document.querySelector('base[target]')?.getAttribute('target') || '';
    const target = (link.getAttribute('target') || baseTarget).toLowerCase();
    if (link.hasAttribute('download')) {
      bypassHref = url.href;
      link.click(); // keeps the browser's download behaviour
    } else if (target && !['_self', '_top', '_parent'].includes(target)) {
      chrome.runtime.sendMessage({ type: 'preflight:open-tab', url: url.href });
    } else {
      window.location.assign(url.href);
    }
  }

  async function checkThenNavigate(link, url) {
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
    const goAnyway = () => navigate(link, url);

    if (!response || response.status === 'allowed') {
      navigate(link, url);
      return;
    }

    if (response.status === 'error') {
      if (response.failMode === 'open') {
        navigate(link, url);
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
      navigate(link, url); // safe pages open with no interruption
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
        navigate(link, url);
      },
    });
  }
})();
