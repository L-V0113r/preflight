/**
 * Actions behind the pop-up's "Report this site" and "Ignore" buttons.
 * Report POSTs to the scanner's /report endpoint, Ignore to /ignore
 * (both in backend/preflight/server.py), which add the site's domain to
 * blocklist_domains.txt or allowlist_domains.txt.
 */

import { getSettings } from './settings.js';

const MAX_KEPT = 200;

// POST {url} to a scanner endpoint. Returns the parsed JSON, or throws.
async function sendToScanner(endpoint, url) {
  const settings = await getSettings();
  if (!settings.token) throw new Error('PreFlight is not set up yet');
  const response = await fetch(`${settings.serverUrl}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-PreFlight-Token': settings.token },
    body: JSON.stringify({ url }),
    cache: 'no-store',
    credentials: 'omit',
  });
  if (!response.ok) throw new Error(`scanner returned ${response.status}`);
  return response.json();
}

// Prepend an entry to a chrome.storage.local list, capped at MAX_KEPT.
async function remember(key, entry) {
  try {
    const { [key]: list = [] } = await chrome.storage.local.get(key);
    list.unshift(entry);
    await chrome.storage.local.set({ [key]: list.slice(0, MAX_KEPT) });
  } catch { /* history is optional */ }
}

// Blocks the reported site's domain via /report. Called from background.js.
export async function onSiteReported(report) {
  await remember('reportedSites', report);
  try {
    const result = await sendToScanner('/report', report.url);
    return { ok: true, message: `Blocked ${result.domain || report.hostname}` };
  } catch (error) {
    return { ok: false, message: `Saved, but couldn't block (${error.message})` };
  }
}

// Trusts the ignored site's domain via /ignore. Called from background.js.
export async function onSiteIgnored(entry) {
  await remember('ignoredSites', entry);
  try {
    const result = await sendToScanner('/ignore', entry.url);
    return { ok: true, message: `Trusting ${result.domain || entry.hostname}` };
  } catch (error) {
    return { ok: false, message: `Couldn't trust (${error.message})` };
  }
}

// Reported entries, newest first.
export async function listReportedSites() {
  const { reportedSites = [] } = await chrome.storage.local.get('reportedSites');
  return reportedSites;
}
