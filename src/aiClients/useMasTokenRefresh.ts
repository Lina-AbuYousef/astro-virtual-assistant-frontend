/**
 * Minimal type describing the HCC Chrome internals used by the token refresh
 * monitor. Defined here instead of using ReturnType<typeof useChrome> because
 * that resolves to `unknown` when used as a parameter type.
 */
export type ChromeAuth = {
  $internal: {
    forceAuthRefresh: () => Promise<{ access_token?: string } | null | undefined>;
  };
};

/**
 * Decode the `exp` claim from a JWT and return it as epoch milliseconds.
 * Returns null if the token is malformed or the claim is missing.
 */
export function getTokenExpMs(token: string): number | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    // base64url → base64
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}

/** How long before the token expires a refresh is attempted. */
const REFRESH_LEAD_MS = 2 * 60 * 1000;
/** Lower bound between cycles after a successful refresh, so a short-lived token can never cause a request loop. */
const MIN_REARM_DELAY_MS = 30 * 1000;
/** Retry backoff after a transient failure: 5s, 15s, 45s, then capped. */
const RETRY_BASE_DELAY_MS = 5 * 1000;
const RETRY_MAX_DELAY_MS = 60 * 1000;
/**
 * Keep retrying until this long after the last token the backend accepted has expired.
 * Past that the workflow has been unauthenticated for a while; the next submit or
 * reopen of the conversation starts a new monitor.
 */
const GIVE_UP_AFTER_EXPIRY_MS = 10 * 60 * 1000;
/** setTimeout fires immediately for delays above 2^31-1 ms; stay well below that. */
const MAX_TIMER_DELAY_MS = 24 * 60 * 60 * 1000;

/**
 * One monitor per session. Identity is the object itself: every callback
 * checks it is still the registered monitor for its session before touching
 * any shared state, so a monitor that was stopped (or replaced after being
 * stopped) can never delete, reschedule, or otherwise affect a newer one.
 */
type Monitor = {
  sessionId: string;
  baseUrl: string;
  chrome: ChromeAuth;
  /** Expiry (epoch ms) of the newest token the backend accepted. */
  syncedExpMs: number;
  /** Consecutive failed cycles, drives the backoff. */
  failures: number;
  timer: ReturnType<typeof setTimeout> | undefined;
  /** Cancels the in-flight refresh request when the monitor is stopped. */
  abort: AbortController;
};

const monitors = new Map<string, Monitor>();

function isCurrent(monitor: Monitor): boolean {
  return monitors.get(monitor.sessionId) === monitor;
}

/** Unregister the monitor, cancel its timer and any in-flight request. No-op for a stale monitor. */
function retire(monitor: Monitor): void {
  if (!isCurrent(monitor)) return;
  monitors.delete(monitor.sessionId);
  if (monitor.timer !== undefined) clearTimeout(monitor.timer);
  monitor.timer = undefined;
  monitor.abort.abort();
}

function arm(monitor: Monitor, delayMs: number): void {
  if (!isCurrent(monitor)) return;
  monitor.timer = setTimeout(() => {
    monitor.timer = undefined;
    // runCycle never rejects: every failure path is handled inside it.
    void runCycle(monitor);
  }, Math.min(delayMs, MAX_TIMER_DELAY_MS));
}

function scheduleRetry(monitor: Monitor, reason: string): void {
  if (!isCurrent(monitor)) return;
  if (Date.now() > monitor.syncedExpMs + GIVE_UP_AFTER_EXPIRY_MS) {
    console.warn(`[MAS token-refresh] ${reason} — giving up, the last synced token expired more than 10 minutes ago`);
    retire(monitor);
    return;
  }
  monitor.failures += 1;
  const delayMs = Math.min(RETRY_BASE_DELAY_MS * 3 ** (monitor.failures - 1), RETRY_MAX_DELAY_MS);
  console.warn(`[MAS token-refresh] ${reason} — retrying in ${delayMs / 1000}s (attempt ${monitor.failures})`);
  arm(monitor, delayMs);
}

async function runCycle(monitor: Monitor): Promise<void> {
  if (!isCurrent(monitor)) return;
  try {
    // TODO(RHCLOUD-52092): Replace with getToken({ minValidity: 420 }) when available.
    const user = await monitor.chrome.$internal.forceAuthRefresh();
    if (!isCurrent(monitor)) return;
    const newToken = (user as { access_token?: string } | null | undefined)?.access_token;
    if (!newToken) {
      scheduleRetry(monitor, 'forceAuthRefresh returned no token');
      return;
    }

    const response = await fetch(`${monitor.baseUrl}/api/sessions/session.token-refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${newToken}`,
      },
      body: JSON.stringify({ sessionId: monitor.sessionId }),
      signal: monitor.abort.signal,
    });
    if (!isCurrent(monitor)) return;

    if (response.status === 403 || response.status === 404 || response.status === 410) {
      // 403 — forbidden; 404 — session ID unknown; 410 — session existed but has ended.
      // Retrying cannot change any of these: stop for good.
      retire(monitor);
      return;
    }
    if (!response.ok) {
      scheduleRetry(monitor, `endpoint returned ${response.status}`);
      return;
    }

    const newExpMs = getTokenExpMs(newToken);
    if (newExpMs === null) {
      console.warn('[MAS token-refresh] refreshed token has no readable exp claim — stopping monitor');
      retire(monitor);
      return;
    }
    if (newExpMs <= monitor.syncedExpMs) {
      // Accepted, but it did not buy any time. Back off instead of looping.
      scheduleRetry(monitor, 'refreshed token did not extend the expiry');
      return;
    }

    monitor.syncedExpMs = newExpMs;
    monitor.failures = 0;
    arm(monitor, Math.max(newExpMs - Date.now() - REFRESH_LEAD_MS, MIN_REARM_DELAY_MS));
  } catch (err) {
    // Stopped while a request was in flight (including our own abort): nothing to do.
    if (!isCurrent(monitor)) return;
    console.error('[MAS token-refresh] request failed', err);
    scheduleRetry(monitor, 'request failed');
  }
}

/**
 * Make sure a token refresh monitor is running for this session.
 *
 * Idempotent: if a monitor already exists for the session this does nothing,
 * so it is safe to call on every submit and whenever a running conversation
 * is reopened. The monitor reschedules itself from each refreshed token's
 * `exp`, so it does not depend on further submits.
 *
 * A monitor fires 2 minutes before the token expires, force-refreshes via
 * HCC Chrome, then POSTs the new token to the MAS backend so the running
 * Temporal workflow picks it up for the next sub-agent call.
 *
 * It stops for good when the backend answers 403 (forbidden), 404 (unknown
 * session) or 410 (session ended). Network errors, 5xx, and other failures are retried with
 * backoff. Never throws.
 */
export function ensureTokenRefreshMonitor(sessionId: string, token: string, baseUrl: string, chrome: ChromeAuth): void {
  if (monitors.has(sessionId)) return;

  const expMs = getTokenExpMs(token);
  if (expMs === null) {
    console.warn('[MAS token-refresh] Could not decode exp claim — monitor not started');
    return;
  }

  const monitor: Monitor = {
    sessionId,
    baseUrl,
    chrome,
    syncedExpMs: expMs,
    failures: 0,
    timer: undefined,
    abort: new AbortController(),
  };
  monitors.set(sessionId, monitor);
  arm(monitor, Math.max(expMs - Date.now() - REFRESH_LEAD_MS, 0));
}

/** Stop the session's monitor, cancelling its timer and any in-flight request. */
export function stopTokenRefreshMonitor(sessionId: string): void {
  const monitor = monitors.get(sessionId);
  if (monitor) retire(monitor);
}

/** Stop every monitor. */
export function stopAllTokenRefreshMonitors(): void {
  Array.from(monitors.values()).forEach(retire);
}

export function isTokenRefreshMonitorActive(sessionId: string): boolean {
  return monitors.has(sessionId);
}
