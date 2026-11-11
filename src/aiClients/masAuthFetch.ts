import { ChromeAuth, ensureTokenRefreshMonitor } from './useMasTokenRefresh';

/** The slice of the HCC Chrome API the MAS fetch wrapper needs. */
export type MasFetchChrome = ChromeAuth & {
  auth: { getToken: () => Promise<string | null | undefined> };
};

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const SUBMIT_PATH = 'api/sessions/user.session.submit';
const CHAT_GET_PATH = 'api/sessions/session.chat.get';

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

function getSessionIdFromBody(body: RequestInit['body'] | undefined): string | undefined {
  if (typeof body !== 'string') return undefined;
  try {
    const sessionId = JSON.parse(body)?.sessionId;
    return typeof sessionId === 'string' && sessionId ? sessionId : undefined;
  } catch {
    return undefined;
  }
}

/** A `Request` (or an object shaped like one) as opposed to a URL string or `URL`. */
function isRequestLike(input: RequestInfo | URL): input is Request {
  return typeof input === 'object' && input !== null && !(input instanceof URL);
}

/**
 * The headers to send, as a plain object: the request's own headers, then the
 * init headers on top, then the bearer token. Accepts a plain object, an array
 * of pairs, or a `Headers` instance (spreading a `Headers` would drop every
 * entry). Names are matched case-insensitively, so a caller-supplied
 * Authorization or Content-Type is replaced, not duplicated.
 */
function buildHeaders(input: RequestInfo | URL, options: RequestInit | undefined, token: string): Record<string, string> {
  const merged = new Map<string, [name: string, value: string]>();
  const add = (name: string, value: string) => merged.set(name.toLowerCase(), [name, value]);
  const addAll = (source: HeadersInit | undefined) => {
    if (!source) return;
    if (Array.isArray(source)) {
      source.forEach(([name, value]) => add(name, value));
    } else if (typeof (source as Headers).forEach === 'function') {
      (source as Headers).forEach((value, name) => add(name, value));
    } else {
      Object.entries(source).forEach(([name, value]) => add(name, value));
    }
  };

  addAll(isRequestLike(input) ? input.headers : undefined);
  addAll(options?.headers);
  add('Authorization', `Bearer ${token}`);
  return Object.fromEntries(merged.values());
}

/**
 * The body of a submit request, read BEFORE the request is sent (a real
 * `Request` body can only be consumed once). Prefers the init body, then the
 * `Request`'s own. Returns undefined when it cannot be read; never throws.
 */
async function readSubmitBody(input: RequestInfo | URL, options: RequestInit | undefined): Promise<RequestInit['body'] | undefined> {
  if (options?.body !== undefined && options.body !== null) return options.body;
  if (!isRequestLike(input)) return undefined;
  const body: unknown = input.body;
  if (typeof body === 'string') return body; // a Request-like object carrying its body as text
  if (typeof input.clone === 'function') {
    try {
      return await input.clone().text();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/**
 * Decide, from a completed MAS request, whether a session's token refresh
 * monitor should start or stop.
 *
 * - submit succeeded      → the session is running: make sure a monitor exists.
 * - chat state is active  → a running conversation was reopened or reconnected
 *                           (page reload, switching conversations): make sure a monitor exists.
 *
 * Deliberately does NOT stop on a COMPLETED/FAILED/CANCELLED chat state: that
 * reading can be stale (it may predate a follow-up submit). The backend's
 * 404/410 on the next refresh is the authoritative signal and stops the
 * monitor on its own.
 */
function observeResponse(
  requestUrl: string,
  submitBody: RequestInit['body'] | undefined,
  response: Response,
  token: string,
  baseUrl: string,
  chrome: MasFetchChrome
): void {
  if (requestUrl.includes(SUBMIT_PATH)) {
    if (!response.ok) return;
    const sessionId = getSessionIdFromBody(submitBody);
    if (sessionId) ensureTokenRefreshMonitor(sessionId, token, baseUrl, chrome);
    return;
  }

  if (requestUrl.includes(CHAT_GET_PATH)) {
    const sessionId = getSessionIdFromUrl(requestUrl);
    if (!sessionId || !response.ok) return;
    // Read a clone so the caller's own consumption of the body is untouched.
    response
      .clone()
      .json()
      .then((chatState: { status?: string } | null) => {
        if (chatState?.status && ACTIVE_STATUSES.has(chatState.status)) {
          ensureTokenRefreshMonitor(sessionId, token, baseUrl, chrome);
        }
      })
      .catch(() => {
        // Not JSON / unreadable — monitoring is best-effort, never affects the request.
      });
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

    const submitBody = isSubmit ? await readSubmitBody(input, options) : undefined;

    const response = await (fetchImpl ?? ((i, o) => fetch(i, o)))(input, {
      ...options,
      headers: buildHeaders(input, options, token),
    });

    try {
      observeResponse(requestUrl, submitBody, response, token, baseUrl, chrome);
    } catch (err) {
      console.warn('[MAS token-refresh] could not update the monitor for this request', err);
    }
    return response;
  };
}
