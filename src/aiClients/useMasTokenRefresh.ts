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

/**
 * Module-level timer map.
 * Keyed by sessionId so each session has at most one pending refresh timer.
 * Lives outside the hook to survive React re-renders.
 */
export const activeRefreshTimers = new Map<string, ReturnType<typeof setTimeout>>();

/**
 * Schedule a mid-session token refresh.
 *
 * Fires 2 minutes before the token expires, force-refreshes via HCC Chrome,
 * then POSTs the new token to the MAS backend so the running Temporal workflow
 * picks it up for the next sub-agent call.
 *
 * Recurses automatically until the backend signals the session has ended
 * (404 response) or an unrecoverable error occurs.
 */
export async function scheduleTokenRefresh(
  sessionId: string,
  token: string,
  baseUrl: string,
  chrome: ChromeAuth
): Promise<void> {
  const existing = activeRefreshTimers.get(sessionId);
  if (existing !== undefined) clearTimeout(existing);

  const expMs = getTokenExpMs(token);
  if (!expMs) {
    console.warn('[MAS token-refresh] Could not decode exp claim — monitor not started');
    return;
  }

  const TWO_MINUTES_MS = 2 * 60 * 1000;
  const delayMs = Math.max(expMs - Date.now() - TWO_MINUTES_MS, 0);

  const timerId = setTimeout(async () => {
    try {
      // TODO(RHCLOUD-52092): Replace with getToken({ minValidity: 420 }) when available.
      const user = await chrome.$internal.forceAuthRefresh();
      const newToken = (user as { access_token?: string } | null | undefined)?.access_token;

      if (!newToken) {
        console.warn('[MAS token-refresh] forceAuthRefresh returned no token — stopping monitor');
        activeRefreshTimers.delete(sessionId);
        return;
      }

      const response = await fetch(`${baseUrl}/api/sessions/session.token-refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${newToken}`,
        },
        body: JSON.stringify({ sessionId, token: newToken }),
      });

      if (response.status === 404) {
        // Session has ended — clean up and stop.
        activeRefreshTimers.delete(sessionId);
        return;
      }

      if (!response.ok) {
        console.warn(`[MAS token-refresh] endpoint returned ${response.status} — stopping monitor`);
        activeRefreshTimers.delete(sessionId);
        return;
      }

      // Success — schedule the next refresh using the new token's exp.
      scheduleTokenRefresh(sessionId, newToken, baseUrl, chrome);
    } catch (err) {
      console.error('[MAS token-refresh] unexpected error — stopping monitor', err);
      activeRefreshTimers.delete(sessionId);
    }
  }, delayMs);

  activeRefreshTimers.set(sessionId, timerId);
}
