/**
 * What the "Report this site" and "Ignore" buttons do.
 *
 * Both send the site to the local PreFlight scanner, which adds its domain to
 * a list it already reads:
 *   Report -> POST /report -> blocklist_domains.txt  (warned about next time)
 *   Ignore -> POST /ignore -> allowlist_domains.txt  (never warned about again)
 *
 * The scanner endpoints live in backend/preflight/server.py, under the
 * "REPORT / IGNORE ENDPOINTS" banner. That is where each button ends up.
 *
 * The call chain:
 *   content/overlay.js      draws the button   ->  onReport() / onIgnore()
 *   content/interceptor.js  sends the message  ->  'preflight:report-site' / 'preflight:ignore-site'
 *   background.js           receives it        ->  onSiteReported() / onSiteIgnored()  <- here
 *   this file               POSTs to the scanner at /report or /ignore
 *
 * A Chrome extension can't change files or train anything itself; it can only
 * ask the local scanner to. So the real work is in the Python endpoint.
 */

import { getSettings } from './settings.js';

const MAX_KEPT = 200;

/**
 * POST {url} to the scanner's /report or /ignore endpoint.
 * Returns the parsed JSON, or throws with a readable message.
 */
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

/** Keep a local copy of the choice too, so the options page can show a history. */
async function remember(key, entry) {
  try {
    const { [key]: list = [] } = await chrome.storage.local.get(key);
    list.unshift(entry);
    await chrome.storage.local.set({ [key]: list.slice(0, MAX_KEPT) });
  } catch { /* history is a convenience; ignore storage errors */ }
}

/**
 * "Report this site": block the site's domain from now on.
 *
 * @param {{url: string, hostname: string, verdict: string|null,
 *          riskScore: number|null, reportedAt: string}} report
 * @returns {Promise<{ok: boolean, message: string}>}
 */
export async function onSiteReported(report) {
  await remember('reportedSites', report);
  try {
    const result = await sendToScanner('/report', report.url);   // --> blocklist
    return { ok: true, message: `Blocked ${result.domain || report.hostname}` };
  } catch (error) {
    // The site is still saved locally above; only the blocking step failed.
    return { ok: false, message: `Saved, but couldn't block (${error.message})` };
  }
}

/**
 * "Ignore": trust the site's domain from now on. Runs before the page opens.
 *
 * @param {{url: string, hostname: string, verdict: string|null,
 *          riskScore: number|null, ignoredAt: string}} entry
 * @returns {Promise<{ok: boolean, message?: string}>}
 */
export async function onSiteIgnored(entry) {
  await remember('ignoredSites', entry);
  try {
    const result = await sendToScanner('/ignore', entry.url);    // --> allowlist
    return { ok: true, message: `Trusting ${result.domain || entry.hostname}` };
  } catch (error) {
    return { ok: false, message: `Couldn't trust (${error.message})` };
  }
}

/** Everything reported so far, newest first. Handy while you're testing. */
export async function listReportedSites() {
  const { reportedSites = [] } = await chrome.storage.local.get('reportedSites');
  return reportedSites;
}
