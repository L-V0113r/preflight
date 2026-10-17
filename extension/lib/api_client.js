/**
 * Talks to the local PreFlight scanner over HTTP.
 *
 * Every request carries the secret token, and every request has a timeout
 * (AbortController), so a hung scan can never freeze the user's browsing.
 */

export class ScannerError extends Error {
  /**
   * @param {string} kind  'unreachable' | 'timeout' | 'unauthorised' | 'bad_response'
   * @param {string} message  human-readable explanation
   */
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

async function request(settings, path, { method = 'GET', body } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.timeoutMs);
  let response;
  try {
    response = await fetch(`${settings.serverUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-PreFlight-Token': settings.token,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'omit',
    });
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new ScannerError('timeout', `The scan took longer than ${settings.timeoutMs / 1000}s.`);
    }
    throw new ScannerError('unreachable', 'The PreFlight scanner is not running on this computer.');
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 401) {
    throw new ScannerError('unauthorised', 'The extension token does not match the scanner. Open PreFlight settings.');
  }
  if (!response.ok) {
    throw new ScannerError('bad_response', `The scanner answered with an error (${response.status}).`);
  }
  try {
    return await response.json();
  } catch {
    throw new ScannerError('bad_response', 'The scanner sent an unreadable answer.');
  }
}

/** Ask the scanner to check one URL. Resolves to a ScanResult object. */
export function scanUrl(settings, url) {
  return request(settings, '/scan', { method: 'POST', body: { url, mode: settings.mode } });
}

/** Check the scanner is running and the token is right. */
export function health(settings) {
  return request(settings, '/health');
}
