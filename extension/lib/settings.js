/**
 * Extension settings, stored with chrome.storage.local.
 *
 * Kept in its own module so the background worker and the options page read
 * and write settings the same way, with the same defaults.
 */

export const DEFAULT_SETTINGS = Object.freeze({
  serverUrl: 'http://127.0.0.1:8765',
  token: '',
  // 'full' downloads and analyses the page; 'url_only' judges the link alone.
  mode: 'full',
  // 'balanced' only interrupts when something points at a problem; 'strict'
  // also asks about every page it couldn't read or doesn't recognise.
  strictness: 'balanced',
  // What to do when the scanner can't be reached: 'ask' the user, 'open'
  // anyway, or 'block' the link.
  failMode: 'ask',
  timeoutMs: 20000,
});

/**
 * The local scanner writes token.json into this extension's folder when it
 * starts (see backend/run_server.py), so setup needs no copy-and-paste.
 * Returns null if the file isn't there (scanner never started).
 */
async function readBundledToken() {
  try {
    const response = await fetch(chrome.runtime.getURL('token.json'), { cache: 'no-store' });
    if (!response.ok) return null;
    const data = await response.json();
    return typeof data.token === 'string' && data.token.length >= 32 ? data : null;
  } catch {
    return null;
  }
}

/** Read all settings, filling any missing values with defaults. */
export async function getSettings() {
  const stored = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  if (!stored.token) {
    const bundled = await readBundledToken();
    if (bundled) {
      stored.token = bundled.token;
      if (typeof bundled.serverUrl === 'string') stored.serverUrl = bundled.serverUrl;
      await chrome.storage.local.set({ token: stored.token, serverUrl: stored.serverUrl });
    }
  }
  return { ...DEFAULT_SETTINGS, ...stored };
}

/** Save a partial settings object after basic validation. */
export async function saveSettings(partial) {
  const clean = {};
  if (typeof partial.serverUrl === 'string') {
    const url = new URL(partial.serverUrl);
    // The scanner must be local; never send links to a remote server.
    if (url.hostname !== '127.0.0.1') {
      throw new Error('The scanner address must be on 127.0.0.1');
    }
    clean.serverUrl = url.origin;
  }
  if (typeof partial.token === 'string') clean.token = partial.token.trim();
  if (['full', 'url_only'].includes(partial.mode)) clean.mode = partial.mode;
  if (['balanced', 'strict'].includes(partial.strictness)) clean.strictness = partial.strictness;
  if (['ask', 'open', 'block'].includes(partial.failMode)) clean.failMode = partial.failMode;
  if (Number.isFinite(partial.timeoutMs)) {
    clean.timeoutMs = Math.min(Math.max(partial.timeoutMs, 3000), 60000);
  }
  await chrome.storage.local.set(clean);
  return getSettings();
}
