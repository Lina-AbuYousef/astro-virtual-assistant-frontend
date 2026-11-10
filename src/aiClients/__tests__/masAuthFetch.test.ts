import { MasFetchChrome, createMasFetch } from '../masAuthFetch';
import { isTokenRefreshMonitorActive, stopAllTokenRefreshMonitors } from '../useMasTokenRefresh';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ sub: 'user-1', exp: expSeconds }));
  return `${header}.${payload}.stub-signature`;
}

function jwtExpiringIn(offsetSeconds: number): string {
  return makeJwt(Math.floor(Date.now() / 1000) + offsetSeconds);
}

const advance = (ms: number) => jest.advanceTimersByTimeAsync(ms);

type FakeResponse = {
  ok: boolean;
  status: number;
  consumed: boolean;
  clone: jest.Mock;
  json: jest.Mock;
};

/** A minimal Response whose clone() is independent, so we can tell who consumed the body. */
function fakeResponse(body: unknown = {}, { ok = true, status = 200 } = {}): FakeResponse {
  const make = (): FakeResponse => {
    const res: FakeResponse = {
      ok,
      status,
      consumed: false,
      clone: jest.fn(() => make()),
      json: jest.fn(async () => {
        res.consumed = true;
        if (body instanceof Error) throw body;
        return body;
      }),
    };
    return res;
  };
  return make();
}

const BASE_URL = 'https://mas.example.com';
const SUBMIT_URL = `${BASE_URL}/api/sessions/user.session.submit`;
const chatUrl = (sessionId: string) => `${BASE_URL}/api/sessions/session.chat.get?sessionId=${sessionId}`;
const deleteUrl = (sessionId: string) => `${BASE_URL}/api/sessions/session.delete?sessionId=${sessionId}`;

const forceAuthRefresh = jest.fn();
const getToken = jest.fn();
const chrome: MasFetchChrome = {
  $internal: { forceAuthRefresh },
  auth: { getToken },
};
const fetchImpl = jest.fn();

let masFetch: ReturnType<typeof createMasFetch>;

function submit(sessionId = 'session-1') {
  return masFetch(SUBMIT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, inputs: { user_prompt: 'hi' }, scope: 'public' }),
  });
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
  jest.clearAllMocks();
  stopAllTokenRefreshMonitors();
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);

  forceAuthRefresh.mockImplementation(async () => ({ access_token: jwtExpiringIn(900) }));
  getToken.mockResolvedValue(jwtExpiringIn(900));
  fetchImpl.mockResolvedValue(fakeResponse());
  masFetch = createMasFetch({ baseUrl: BASE_URL, chrome, fetchImpl });
});

afterEach(() => {
  stopAllTokenRefreshMonitors();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

// ─── Submit ───────────────────────────────────────────────────────────────────

describe('submit', () => {
  it('force-refreshes the token, sends it, and starts the monitor after the submit succeeds', async () => {
    const fresh = jwtExpiringIn(900);
    forceAuthRefresh.mockResolvedValueOnce({ access_token: fresh });

    await submit('session-1');

    expect(getToken).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledWith(
      SUBMIT_URL,
      expect.objectContaining({
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fresh}` },
      })
    );
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('does NOT start the monitor before the submit request has succeeded', async () => {
    let seenWhileInFlight: boolean | undefined;
    fetchImpl.mockImplementationOnce(async () => {
      seenWhileInFlight = isTokenRefreshMonitorActive('session-1');
      return fakeResponse();
    });

    await submit('session-1');

    expect(seenWhileInFlight).toBe(false);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it.each([400, 401, 404, 500, 503])('does not start a monitor when the submit returns %i, and returns that response', async (status) => {
    const response = fakeResponse({}, { ok: false, status });
    fetchImpl.mockResolvedValueOnce(response);

    await expect(submit('session-1')).resolves.toBe(response);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);
  });

  it('does not start a monitor when the submit request rejects (network error)', async () => {
    fetchImpl.mockRejectedValueOnce(new Error('Network error'));

    await expect(submit('session-1')).rejects.toThrow('Network error');

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('does not start a monitor when the submit is aborted', async () => {
    fetchImpl.mockRejectedValueOnce(new DOMException('aborted', 'AbortError'));

    await expect(submit('session-1')).rejects.toThrow();

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('fails without sending anything when the auth refresh returns no token', async () => {
    forceAuthRefresh.mockResolvedValueOnce(null);

    await expect(submit('session-1')).rejects.toThrow('Failed to refresh authentication');

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('propagates a forceAuthRefresh failure and starts nothing', async () => {
    forceAuthRefresh.mockRejectedValueOnce(new Error('SSO down'));

    await expect(submit('session-1')).rejects.toThrow('SSO down');

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
  });

  it.each([
    ['a body with no sessionId', JSON.stringify({ inputs: {} })],
    ['a body that is not JSON', 'not json'],
    ['a non-string body', new Uint8Array([1, 2, 3])],
    ['no body', undefined],
    ['an empty sessionId', JSON.stringify({ sessionId: '' })],
    ['a non-string sessionId', JSON.stringify({ sessionId: 123 })],
  ])('still completes the submit and starts no monitor for %s', async (_name, body) => {
    const response = fakeResponse();
    fetchImpl.mockResolvedValueOnce(response);

    await expect(masFetch(SUBMIT_URL, { method: 'POST', body: body as RequestInit['body'] })).resolves.toBe(response);

    expect(jest.getTimerCount()).toBe(0);
  });

  it('still completes the submit when the refreshed token has no readable exp', async () => {
    forceAuthRefresh.mockResolvedValueOnce({ access_token: 'opaque-token' });
    const response = fakeResponse();
    fetchImpl.mockResolvedValueOnce(response);

    await expect(submit('session-1')).resolves.toBe(response);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('a follow-up submit for the same session keeps the one running monitor (ensure, not replace)', async () => {
    await submit('session-1');
    expect(jest.getTimerCount()).toBe(1);

    await submit('session-1');
    await submit('session-1');

    expect(jest.getTimerCount()).toBe(1);
    await advance(13 * 60 * 1000);
    // One monitor → one refresh attempt, not three.
    expect(forceAuthRefresh).toHaveBeenCalledTimes(3 + 1); // 3 submits' own refreshes + 1 monitor cycle
  });

  it('concurrent submits for the same session still produce a single monitor', async () => {
    await Promise.all([submit('session-1'), submit('session-1'), submit('session-1')]);

    expect(jest.getTimerCount()).toBe(1);
  });

  it('keeps separate monitors for different sessions', async () => {
    await submit('session-A');
    await submit('session-B');

    expect(isTokenRefreshMonitorActive('session-A')).toBe(true);
    expect(isTokenRefreshMonitorActive('session-B')).toBe(true);
    expect(jest.getTimerCount()).toBe(2);
  });
});

// ─── Other requests ───────────────────────────────────────────────────────────

describe('requests other than submit', () => {
  it('uses the current token (no forced refresh) and merges existing headers', async () => {
    getToken.mockResolvedValueOnce('current-token');

    await masFetch(`${BASE_URL}/api/sessions/session.user.list`, { headers: { Accept: 'application/json' } });

    expect(forceAuthRefresh).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledWith(
      `${BASE_URL}/api/sessions/session.user.list`,
      expect.objectContaining({ headers: { Accept: 'application/json', Authorization: 'Bearer current-token' } })
    );
    expect(jest.getTimerCount()).toBe(0);
  });

  it.each([null, undefined, ''])('fails when there is no current token (%p)', async (value) => {
    getToken.mockResolvedValueOnce(value);

    await expect(masFetch(`${BASE_URL}/api/sessions/session.user.list`)).rejects.toThrow('User is not authenticated');

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('accepts a URL object and a Request-like input', async () => {
    await masFetch(new URL(SUBMIT_URL), {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'session-url' }),
    });
    expect(isTokenRefreshMonitorActive('session-url')).toBe(true);

    await masFetch({ url: SUBMIT_URL } as unknown as Request, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'session-req' }),
    });
    expect(isTokenRefreshMonitorActive('session-req')).toBe(true);
  });
});

// ─── Reopening / reconnecting a conversation ──────────────────────────────────

describe('reopening a conversation (session.chat.get)', () => {
  it.each(['RUNNING', 'QUEUED'])('starts the monitor when the session is %s (e.g. after a page reload)', async (status) => {
    fetchImpl.mockResolvedValueOnce(fakeResponse({ messages: [], status }));

    await masFetch(chatUrl('session-1'));
    await advance(0);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it.each(['COMPLETED', 'FAILED', 'CANCELLED', 'PENDING', 'LOCKED', 'IN_USE'])('starts no monitor when the session is %s', async (status) => {
    fetchImpl.mockResolvedValueOnce(fakeResponse({ messages: [], status }));

    await masFetch(chatUrl('session-1'));
    await advance(0);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('does not stop a running monitor on a terminal status (that reading can be stale; 404/410 decides)', async () => {
    await submit('session-1');
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
    fetchImpl.mockResolvedValueOnce(fakeResponse({ messages: [], status: 'COMPLETED' }));

    await masFetch(chatUrl('session-1'));
    await advance(0);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('does not add a second monitor when one is already running', async () => {
    await submit('session-1');
    fetchImpl.mockResolvedValueOnce(fakeResponse({ messages: [], status: 'RUNNING' }));

    await masFetch(chatUrl('session-1'));
    await advance(0);

    expect(jest.getTimerCount()).toBe(1);
  });

  it('reads the state from a clone, leaving the body for the caller', async () => {
    const response = fakeResponse({ messages: [], status: 'RUNNING' });
    fetchImpl.mockResolvedValueOnce(response);

    const returned = (await masFetch(chatUrl('session-1'))) as unknown as FakeResponse;
    await advance(0);

    expect(returned).toBe(response);
    expect(response.clone).toHaveBeenCalledTimes(1);
    expect(response.consumed).toBe(false);
  });

  it.each([
    ['a non-OK response', fakeResponse({ status: 'RUNNING' }, { ok: false, status: 500 })],
    ['a body that is not JSON', fakeResponse(new Error('Unexpected token'))],
    ['a body with no status', fakeResponse({ messages: [] })],
    ['a null body', fakeResponse(null)],
  ])('starts no monitor and does not throw on %s', async (_name, response) => {
    fetchImpl.mockResolvedValueOnce(response);

    await expect(masFetch(chatUrl('session-1'))).resolves.toBe(response);
    await advance(0);

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
  });

  it('starts no monitor when the URL has no sessionId', async () => {
    fetchImpl.mockResolvedValueOnce(fakeResponse({ status: 'RUNNING' }));

    await masFetch(`${BASE_URL}/api/sessions/session.chat.get`);
    await advance(0);

    expect(jest.getTimerCount()).toBe(0);
  });

  it('never breaks the request when the monitor bookkeeping throws', async () => {
    const response = fakeResponse({ status: 'RUNNING' });
    response.clone.mockImplementation(() => {
      throw new Error('clone failed');
    });
    fetchImpl.mockResolvedValueOnce(response);

    await expect(masFetch(chatUrl('session-1'))).resolves.toBe(response);

    expect(console.warn).toHaveBeenCalled();
  });
});

// ─── Deleting a conversation ──────────────────────────────────────────────────

describe('deleting a conversation (session.delete)', () => {
  it('stops that session’s monitor after a successful delete', async () => {
    await submit('session-1');
    await submit('session-2');

    await masFetch(deleteUrl('session-1'), { method: 'DELETE' });

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(isTokenRefreshMonitorActive('session-2')).toBe(true);
  });

  it('keeps the monitor when the delete fails', async () => {
    await submit('session-1');
    fetchImpl.mockResolvedValueOnce(fakeResponse({}, { ok: false, status: 500 }));

    await masFetch(deleteUrl('session-1'), { method: 'DELETE' });

    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('ignores a non-DELETE request to the same path', async () => {
    await submit('session-1');

    await masFetch(deleteUrl('session-1'), { method: 'GET' });

    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });
});
