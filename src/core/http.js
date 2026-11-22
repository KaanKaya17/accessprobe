// fetch with a short, polite retry on rate limits (429, and 503 with Retry-After).
// Backends throttle bursts, auth endpoints especially. A request that is still throttled after
// the retries is reported as RATE_LIMITED: the client turns it into an inconclusive result
// (status 0), so a throttled check can never pass as "refused".

const MAX_TRIES = 3;
const MAX_WAIT_MS = 8000;

export const RATE_LIMITED = 'rate limited (HTTP 429, still after 3 tries) — wait a few minutes and run again';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function waitFor(res, attempt) {
  const h = res.headers.get('retry-after');
  const secs = h && /^\d+(\.\d+)?$/.test(h.trim()) ? Number(h) : h && !Number.isNaN(Date.parse(h)) ? (Date.parse(h) - Date.now()) / 1000 : null;
  const ms = secs !== null ? secs * 1000 : 1000 * 2 ** attempt; // 1s, 2s without a hint
  return Math.max(0, Math.min(ms, MAX_WAIT_MS));
}

export const throttled = (res) => res.status === 429 || (res.status === 503 && res.headers.has('retry-after'));

// → the last Response; callers check throttled(res) to see if it never got through
export async function fetchRetry(url, init, { timeoutMs, tries = MAX_TRIES, wait = waitFor } = {}) {
  let res;
  for (let attempt = 0; attempt < tries; attempt++) {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    if (!throttled(res) || attempt === tries - 1) return res;
    await res.arrayBuffer().catch(() => {}); // free the connection
    await sleep(wait(res, attempt));
  }
  return res;
}
