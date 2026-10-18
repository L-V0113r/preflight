/**
 * PreFlight background service worker.
 *
 * Content scripts can't call the local scanner themselves (page context,
 * CORS and secrecy of the token), so they send a message here and this
 * worker does the HTTP call. The token never enters any web page.
 */

import { getSettings } from './lib/settings.js';
import { scanUrl, health, ScannerError } from './lib/api_client.js';
import { getCachedResult, cacheResult, isSiteAllowed, allowSite } from './lib/session_state.js';
import { onSiteReported, onSiteIgnored } from './lib/report_action.js';
import { STATUS_ALARM, refreshStatus, statusFromScan, startStatusChecks } from './lib/status.js';

const inFlight = new Map(); // url -> Promise, so double-clicks share one scan

/** Scan a URL, using the cache and de-duplicating concurrent requests. */
async function scanWithCache(settings, url) {
  const key = `${settings.mode}|${settings.strictness}|${url}`;
  const cached = getCachedResult(key);
  if (cached) return cached;
  if (!inFlight.has(key)) {
    // Only real requests update the icon status; cached results say nothing
    // about whether the scanner is still running.
    const promise = scanUrl(settings, url)
      .then((result) => {
        cacheResult(key, result);
        statusFromScan(null);
        return result;
      })
      .catch((error) => {
        statusFromScan(error);
        throw error;
      })
      .finally(() => inFlight.delete(key));
    inFlight.set(key, promise);
  }
  return inFlight.get(key);
}

const handlers = {
  async 'preflight:scan'(message) {
    const url = new URL(message.url);
    const settings = await getSettings();
    if (await isSiteAllowed(url.hostname)) {
      return { status: 'allowed' };
    }
    if (!settings.token) {
      return {
        status: 'error',
        kind: 'not_configured',
        message: 'PreFlight is not set up yet. Start the scanner (double-click "Start PreFlight.bat"), then try again.',
        failMode: settings.failMode,
      };
    }
    try {
      const result = await scanWithCache(settings, url.href);
      return { status: 'ok', result };
    } catch (error) {
      const known = error instanceof ScannerError;
      return {
        status: 'error',
        kind: known ? error.kind : 'internal',
        message: known ? error.message : 'Something went wrong inside PreFlight.',
        failMode: settings.failMode,
      };
    }
  },

  // Calls onSiteReported in lib/report_action.js.
  async 'preflight:report-site'(message) {
    const url = new URL(message.url);
    try {
      const outcome = await onSiteReported({
        url: url.href,
        hostname: url.hostname,
        verdict: message.verdict ?? null,
        riskScore: message.riskScore ?? null,
        reportedAt: new Date().toISOString(),
      });
      return { status: 'ok', ...outcome };
    } catch (error) {
      return { status: 'error', ok: false, message: `Report failed: ${error.message}` };
    }
  },

  // Calls onSiteIgnored in lib/report_action.js.
  async 'preflight:ignore-site'(message) {
    const url = new URL(message.url);
    try {
      const outcome = await onSiteIgnored({
        url: url.href,
        hostname: url.hostname,
        verdict: message.verdict ?? null,
        riskScore: message.riskScore ?? null,
        ignoredAt: new Date().toISOString(),
      });
      return { status: 'ok', ...(outcome || {}) };
    } catch (error) {
      return { status: 'error', ok: false, message: `Ignore failed: ${error.message}` };
    }
  },

  async 'preflight:allow-site'(message) {
    await allowSite(String(message.hostname));
    return { status: 'ok' };
  },

  // mode: 'foreground' | 'background' (new tab) or 'window' (new window).
  async 'preflight:open-tab'(message, sender) {
    const url = new URL(message.url);
    if (!['http:', 'https:'].includes(url.protocol)) return { status: 'ignored' };
    if (message.mode === 'window') {
      await chrome.windows.create({ url: url.href });
      return { status: 'ok' };
    }
    await chrome.tabs.create({
      url: url.href,
      active: message.mode !== 'background',
      openerTabId: sender.tab?.id,
      index: sender.tab ? sender.tab.index + 1 : undefined,
    });
    return { status: 'ok' };
  },

  async 'preflight:health'() {
    const settings = await getSettings();
    try {
      const info = await health(settings);
      refreshStatus();
      return { status: 'ok', health: info };
    } catch (error) {
      refreshStatus();
      return { status: 'error', message: error.message };
    }
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only accept messages from this extension's own scripts.
  if (sender.id !== chrome.runtime.id || !message || !handlers[message.type]) {
    return false;
  }
  handlers[message.type](message, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ status: 'error', kind: 'internal', message: String(error) }));
  return true; // keep the channel open for the async response
});

// Clicking the toolbar icon opens the settings page.
chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());

// First install: open settings so the user can check the connection.
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') chrome.runtime.openOptionsPage();
  startStatusChecks();
});

// Icon hover text: checked at browser start-up and every 30 seconds.
chrome.runtime.onStartup.addListener(startStatusChecks);
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === STATUS_ALARM) refreshStatus();
});

// The worker is restarted after idling; check straight away each time it wakes.
refreshStatus();
