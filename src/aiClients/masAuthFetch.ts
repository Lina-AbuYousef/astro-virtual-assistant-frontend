import { ChromeAuth, ensureTokenRefreshMonitor, isTokenRefreshMonitorActive } from './useMasTokenRefresh';

/** The slice of the HCC Chrome API the MAS fetch wrapper needs. */
export type MasFetchChrome = ChromeAuth & {
  auth: { getToken: () => Promise<string | null | undefined> };
};

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const SUBMIT_PATH = 'api/sessions/user.session.submit';
const CHAT_GET_PATH = 'api/sessions/session.chat.get';
const STATUS_PATH = 'api/sessions/session.status.get';

/** Backend statuses in which a session accepts token refreshes (anything else answers 410). */
const ACTIVE_STATUSES = new Set(['RUNNING', 'QUEUED']);

function getRequestUrl(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input?.url ?? '';
}

function getSessionIdFromUrl(requestUrl: string): string | undefined {
  try {
    return new URL(requestUrl, 'http://localhost').searchParams.get('sessionId') || undefined;
  } catch {
    return undefined;
  }
}

function getSessionIdFromBody(body: RequestInit['body']): string | undefined {
  if (typeof body !== 'string') return undefined;
  try {
    const sessionId = JSON.parse(body)?.sessionId;
    return typeof sessionId === 'string' && sessionId ? sessionId : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Ask the backend whether a session is running and, if so, make sure its token
 * refresh monitor exists. Used when a conversation is reopened (page reload,
 * switching conversations).
 *
 * Uses session.status.get, which any logged-in user may call. The history
 * request the UI makes (session.chat.get) is admin-only, so its answer cannot
 * be relied on. Best-effort: any failure leaves things as they were.
 */
function ensureMonitorIfSessionIsActive(sessionId: string, token: string, baseUrl: string, chrome: MasFetchChrome, doFetch: FetchLike): void {
  if (isTokenRefreshMonitorActive(sessionId)) return;
  doFetch(`${baseUrl}/${STATUS_PATH}?sessionId=${encodeURIComponent(sessionId)}`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  })
    .then((response) => (response.ok ? response.json() : null))
    .then((status) => {
      // The endpoint answers with the bare status string, e.g. "RUNNING".
      if (typeof status === 'string' && ACTIVE_STATUSES.has(status)) {
        ensureTokenRefreshMonitor(sessionId, token, baseUrl, chrome);
      }
    })
    .catch(() => {
      // Unreachable, not OK, or unreadable — monitoring is best-effort.
    });
}

/**
 * Decide, from a completed MAS request, whether a session's token refresh
 * monitor should start.
 *
 * - submit succeeded       → the session is running: make sure a monitor exists.
 * - history was requested  → a conversation was reopened (page reload, switching
 *                            conversations): if the session is still running,
 *                            make sure a monitor exists. The answer to the history
 *                            request itself is irrelevant, it may be forbidden.
 *
 * Monitors are never stopped from here. A stale COMPLETED/FAILED reading could
 * predate a follow-up submit; the backend's 404/410 on the next refresh is the
 * authoritative signal and stops the monitor on its own.
 */
function observeResponse(
  requestUrl: string,
  options: RequestInit | undefined,
  response: Response,
  token: string,
  baseUrl: string,
  chrome: MasFetchChrome,
  doFetch: FetchLike
): void {
  if (requestUrl.includes(SUBMIT_PATH)) {
    if (!response.ok) return;
    const sessionId = getSessionIdFromBody(options?.body);
    if (sessionId) ensureTokenRefreshMonitor(sessionId, token, baseUrl, chrome);
    return;
  }

  if (requestUrl.includes(CHAT_GET_PATH)) {
    const sessionId = getSessionIdFromUrl(requestUrl);
    if (sessionId) ensureMonitorIfSessionIsActive(sessionId, token, baseUrl, chrome, doFetch);
  }
}

/**
 * Build the `fetchFunction` for MASClient.
 *
 * Adds the bearer token to every request (force-refreshed for a submit, the
 * current one otherwise) and keeps the token refresh monitor in step with the
 * session lifecycle. Monitoring is best-effort: it can never fail, delay, or
 * alter the request itself.
 */
export function createMasFetch({ baseUrl, chrome, fetchImpl }: { baseUrl: string; chrome: MasFetchChrome; fetchImpl?: FetchLike }): FetchLike {
  const doFetch: FetchLike = fetchImpl ?? ((i, o) => fetch(i, o));
  return async (input, options) => {
    const requestUrl = getRequestUrl(input);
    const isSubmit = !!requestUrl && requestUrl.includes(SUBMIT_PATH);

    // TODO(RHCLOUD-52092): Replace with getToken({ minValidity: 420 }) when available.
    let token: string | null | undefined;
    if (isSubmit) {
      const user = await chrome.$internal.forceAuthRefresh();
      token = (user as { access_token?: string } | null | undefined)?.access_token;
      if (!token) {
        throw new Error('Failed to refresh authentication');
      }
    } else {
      token = await chrome.auth.getToken();
    }
    if (!token) {
      throw new Error('User is not authenticated');
    }

    const response = await doFetch(input, {
      ...options,
      headers: {
        ...options?.headers,
        Authorization: `Bearer ${token}`,
      },
    });

    try {
      observeResponse(requestUrl, options, response, token, baseUrl, chrome, doFetch);
    } catch (err) {
      console.warn('[MAS token-refresh] could not update the monitor for this request', err);
    }
    return response;
  };
}
