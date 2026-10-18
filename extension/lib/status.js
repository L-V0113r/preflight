/**
 * Hover text on the toolbar icon, showing whether the local scanner is
 * running. Checked when the browser starts, every 30 seconds (STATUS_ALARM),
 * and after every scan.
 */

import { getSettings } from './settings.js';
import { health, ScannerError } from './api_client.js';

export const STATUS_ALARM = 'preflight-status';
const CHECK_TIMEOUT_MS = 3000;

// Headline and explanation shown for each state.
const MESSAGES = {
  running: ['PreFlight is RUNNING', 'Links to other sites are checked before they open.'],
  stopped: ['PreFlight is NOT RUNNING', 'Links are not being checked. Start it with "Start PreFlight.bat".'],
  not_connected: ['PreFlight scanner is running, but NOT CONNECTED',
    'The extension token does not match. Open PreFlight settings and paste the token again.'],
  not_set_up: ['PreFlight is NOT SET UP', 'Start the scanner once with "Start PreFlight.bat".'],
  not_responding: ['PreFlight is NOT RESPONDING', 'The scanner is not answering. Try restarting it.'],
};

function timeNow() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

async function show(state, extra = '') {
  const [headline, detail] = MESSAGES[state];
  const lines = [headline, extra || detail, `Last checked ${timeNow()}`];
  try {
    await chrome.action.setTitle({ title: lines.join('\n') });
  } catch { /* the icon text is cosmetic; never let it break a scan */ }
}

// Maps a ScannerError kind (see api_client.js) to a status.
function stateForError(error) {
  if (!(error instanceof ScannerError)) return 'not_responding';
  if (error.kind === 'unreachable') return 'stopped';
  if (error.kind === 'unauthorised') return 'not_connected';
  return 'not_responding';
}

// Asks the scanner's /health endpoint and updates the hover text.
export async function refreshStatus() {
  const settings = await getSettings();
  if (!settings.token) {
    await show('not_set_up');
    return;
  }
  try {
    const info = await health({ ...settings, timeoutMs: CHECK_TIMEOUT_MS });
    const model = info.model_loaded ? 'AI model loaded' : 'rules only, no AI model';
    await show('running', `Scanner ${info.version}, ${model}.`);
  } catch (error) {
    await show(stateForError(error));
  }
}

// Updates the hover text from a scan's outcome, without another request.
export async function statusFromScan(error) {
  await show(error ? stateForError(error) : 'running');
}

// Schedules the 30-second check. Chrome's shortest alarm period is 30 seconds.
export function startStatusChecks() {
  chrome.alarms.create(STATUS_ALARM, { periodInMinutes: 0.5 });
  refreshStatus();
}
