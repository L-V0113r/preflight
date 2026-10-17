/**
 * Short-lived state shared by the background worker:
 *
 * - a results cache, so clicking the same link twice doesn't scan twice;
 * - the sites the user chose to "open anyway" during this browser session.
 *
 * MV3 service workers are stopped when idle, so anything that must survive
 * that lives in chrome.storage.session (cleared when the browser closes).
 */

const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 200;
const memoryCache = new Map(); // url -> { result, expires }

export function getCachedResult(url) {
  const entry = memoryCache.get(url);
  if (!entry) return null;
  if (entry.expires < Date.now()) {
    memoryCache.delete(url);
    return null;
  }
  return entry.result;
}

export function cacheResult(url, result) {
  // Never cache failures: the next click should try again.
  if (!result || result.verdict === 'error') return;
  memoryCache.set(url, { result, expires: Date.now() + CACHE_TTL_MS });
  if (memoryCache.size > CACHE_MAX) {
    memoryCache.delete(memoryCache.keys().next().value); // drop the oldest
  }
}

export async function isSiteAllowed(hostname) {
  const { allowedSites = [] } = await chrome.storage.session.get('allowedSites');
  return allowedSites.includes(hostname);
}

export async function allowSite(hostname) {
  const { allowedSites = [] } = await chrome.storage.session.get('allowedSites');
  if (!allowedSites.includes(hostname)) {
    allowedSites.push(hostname);
    await chrome.storage.session.set({ allowedSites });
  }
}
