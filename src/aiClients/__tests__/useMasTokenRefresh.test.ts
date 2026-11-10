import {
  ChromeAuth,
  ensureTokenRefreshMonitor,
  getTokenExpMs,
  isTokenRefreshMonitorActive,
  stopAllTokenRefreshMonitors,
  stopTokenRefreshMonitor,
} from '../useMasTokenRefresh';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a compact JWT with a given exp (Unix seconds).
 * Signature part is a stub — we never verify it here.
 */
function makeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ sub: 'user-1', exp: expSeconds }));
  return `${header}.${payload}.stub-signature`;
}

/** JWT whose exp is `offsetSeconds` from the (fake) current time. */
function jwtExpiringIn(offsetSeconds: number): string {
  return makeJwt(Math.floor(Date.now() / 1000) + offsetSeconds);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const advance = (ms: number) => jest.advanceTimersByTimeAsync(ms);

/** A 15-minute token fires its first refresh 13 minutes (15 − 2) after it is issued. */
const FIRST_FIRE_MS = 13 * 60 * 1000;
const SECOND = 1000;
const HOUR = 60 * 60 * 1000;

// ─── Mock chrome ─────────────────────────────────────────────────────────────

const mockForceAuthRefresh = jest.fn();

const mockChrome: ChromeAuth = {
  $internal: {
    forceAuthRefresh: mockForceAuthRefresh,
  },
};

const BASE_URL = 'https://mas.example.com';
const REFRESH_URL = `${BASE_URL}/api/sessions/session.token-refresh`;

function start(sessionId = 'session-1', token = jwtExpiringIn(900)) {
  ensureTokenRefreshMonitor(sessionId, token, BASE_URL, mockChrome);
}

const fetchMock = () => global.fetch as jest.Mock;

// ─── Setup / teardown ────────────────────────────────────────────────────────

beforeEach(() => {
  jest.useFakeTimers();
  // Whole second so Math.floor(Date.now() / 1000) has no remainder and delays are exact.
  jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
  jest.clearAllMocks();
  stopAllTokenRefreshMonitors();

  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);

  // Default: forceAuthRefresh returns a fresh token that extends the expiry.
  mockForceAuthRefresh.mockImplementation(async () => ({ access_token: jwtExpiringIn(900) }));

  // Default: token-refresh endpoint returns 200
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
});

afterEach(() => {
  stopAllTokenRefreshMonitors();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

// ─── getTokenExpMs ────────────────────────────────────────────────────────────

describe('getTokenExpMs', () => {
  it('returns exp in milliseconds for a valid JWT', () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 900;
    expect(getTokenExpMs(makeJwt(expSeconds))).toBe(expSeconds * 1000);
  });

  it('returns null for a token with fewer than 3 parts', () => {
    expect(getTokenExpMs('only.two')).toBeNull();
    expect(getTokenExpMs('one')).toBeNull();
  });

  it('returns null when the payload is not valid JSON', () => {
    expect(getTokenExpMs('header.!!!notbase64!!!.sig')).toBeNull();
  });

  it('returns null when exp claim is missing', () => {
    const header = btoa(JSON.stringify({ alg: 'RS256' }));
    const payload = btoa(JSON.stringify({ sub: 'user-1' }));
    expect(getTokenExpMs(`${header}.${payload}.sig`)).toBeNull();
  });

  it('returns null when exp is not a number', () => {
    const header = btoa(JSON.stringify({ alg: 'RS256' }));
    const payload = btoa(JSON.stringify({ exp: 'not-a-number' }));
    expect(getTokenExpMs(`${header}.${payload}.sig`)).toBeNull();
  });

  it('handles base64url encoding (- and _ characters)', () => {
    const expSeconds = 9999999999;
    expect(getTokenExpMs(makeJwt(expSeconds))).toBe(expSeconds * 1000);
  });
});

// ─── Starting a monitor ───────────────────────────────────────────────────────

describe('ensureTokenRefreshMonitor', () => {
  it('registers a monitor for the session', () => {
    start();
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('does not start a monitor when the JWT has no exp claim', () => {
    ensureTokenRefreshMonitor('session-1', 'bad.token.here', BASE_URL, mockChrome);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);
  });

  it('is idempotent: a second call for the same session does not add a second monitor', async () => {
    start();
    start();
    start();

    await advance(FIRST_FIRE_MS);

    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    expect(fetchMock()).toHaveBeenCalledTimes(1);
  });

  it('keeps the running schedule when called again with a different token (ensure, not replace)', async () => {
    start('session-1', jwtExpiringIn(900));
    start('session-1', jwtExpiringIn(3600)); // would be a much later deadline if it replaced

    await advance(FIRST_FIRE_MS);

    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });

  it('runs independent monitors for different sessions', async () => {
    start('session-A', jwtExpiringIn(900));
    start('session-B', jwtExpiringIn(600));

    await advance(8 * 60 * 1000); // B fires at 8 min (10 − 2)
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetchMock().mock.calls[0][1].body)).toEqual({ sessionId: 'session-B' });

    await advance(5 * 60 * 1000); // A fires at 13 min
    expect(JSON.parse(fetchMock().mock.calls[1][1].body)).toEqual({ sessionId: 'session-A' });
  });

  it('fires exactly 2 minutes before token expiry', async () => {
    start('session-1', jwtExpiringIn(900));

    await advance(FIRST_FIRE_MS - 1);
    expect(mockForceAuthRefresh).not.toHaveBeenCalled();

    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });

  it('fires immediately when the token is already within the 2-minute buffer', async () => {
    start('session-1', jwtExpiringIn(60));

    await advance(0);

    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });

  it('POSTs the new token to the correct endpoint with the correct body', async () => {
    start();
    mockForceAuthRefresh.mockResolvedValueOnce({ access_token: 'fresh-token' });

    await advance(FIRST_FIRE_MS);

    // The fresh token travels only in the Authorization header (validated by
    // @require_auth on the backend); the body carries just the sessionId.
    expect(fetchMock()).toHaveBeenCalledWith(
      REFRESH_URL,
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Authorization: 'Bearer fresh-token',
        }),
        body: JSON.stringify({ sessionId: 'session-1' }),
        signal: expect.any(AbortSignal),
      })
    );
  });

  it('caps very long delays so the browser timer cannot overflow into an immediate fire', async () => {
    start('session-1', makeJwt(Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 3600));

    await advance(23 * HOUR);
    expect(mockForceAuthRefresh).not.toHaveBeenCalled();

    await advance(HOUR + SECOND);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });
});

// ─── Successful refresh ───────────────────────────────────────────────────────

describe('after a successful refresh', () => {
  it('reschedules from the new token expiry', async () => {
    start('session-1', jwtExpiringIn(900));

    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);

    // New token is valid for 15 minutes from the first refresh → next fire 13 minutes later.
    await advance(FIRST_FIRE_MS - 1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('never reschedules sooner than 30 seconds even if the new token expires very soon', async () => {
    start('session-1', jwtExpiringIn(900));
    // Extends the expiry by only 10 s, leaving 130 s → 10 s until the 2-minute lead.
    mockForceAuthRefresh.mockImplementationOnce(async () => ({ access_token: jwtExpiringIn(130) }));

    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);

    await advance(30 * SECOND - 1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
  });

  it('does not loop when the refreshed token does not extend the expiry (backs off instead)', async () => {
    const sameToken = jwtExpiringIn(900);
    mockForceAuthRefresh.mockResolvedValue({ access_token: sameToken });
    start('session-1', sameToken);

    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);

    // Same expiry as already synced → retry after 5 s, not immediately.
    await advance(5 * SECOND - 1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });

  it('stops when the refreshed token has no readable exp (cannot schedule from it)', async () => {
    mockForceAuthRefresh.mockResolvedValue({ access_token: 'opaque-token' });
    start();

    await advance(FIRST_FIRE_MS);

    expect(fetchMock()).toHaveBeenCalledTimes(1);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);
  });
});

// ─── Permanent stop ───────────────────────────────────────────────────────────

describe.each([
  [404, 'session unknown'],
  [410, 'session ended'],
])('when the backend returns %i (%s)', (status) => {
  it('stops for good and makes no further requests', async () => {
    fetchMock().mockResolvedValue({ ok: false, status });
    start();

    await advance(FIRST_FIRE_MS);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);

    await advance(2 * HOUR);
    expect(fetchMock()).toHaveBeenCalledTimes(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
  });

  it('allows a later ensure (e.g. the next submit) to start a fresh monitor', async () => {
    fetchMock().mockResolvedValueOnce({ ok: false, status });
    start();
    await advance(FIRST_FIRE_MS);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);

    start();

    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });
});

// ─── Transient failures are retried, not fatal ────────────────────────────────

describe('transient failures', () => {
  const failures: Array<[string, () => void]> = [
    ['forceAuthRefresh returns no token', () => mockForceAuthRefresh.mockResolvedValueOnce(null)],
    ['forceAuthRefresh throws', () => mockForceAuthRefresh.mockRejectedValueOnce(new Error('SSO network failure'))],
    ['the request fails (network error)', () => fetchMock().mockRejectedValueOnce(new Error('Network error'))],
    ['the backend returns 500', () => fetchMock().mockResolvedValueOnce({ ok: false, status: 500 })],
    ['the backend returns 503', () => fetchMock().mockResolvedValueOnce({ ok: false, status: 503 })],
    ['the backend returns 401', () => fetchMock().mockResolvedValueOnce({ ok: false, status: 401 })],
  ];

  it.each(failures)('keeps the monitor and retries after 5 s when %s', async (_name, arrange) => {
    arrange();
    start();

    await advance(FIRST_FIRE_MS);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);

    await advance(5 * SECOND - 1);
    expect(mockForceAuthRefresh.mock.calls.length).toBeLessThanOrEqual(1);

    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
    // The retry succeeds and the monitor carries on.
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
    expect(fetchMock().mock.calls.length).toBeGreaterThanOrEqual(1);
  });

  it('backs off 5 s, 15 s, 45 s, then 60 s while the backend keeps failing', async () => {
    fetchMock().mockResolvedValue({ ok: false, status: 500 });
    start('session-1', jwtExpiringIn(900));

    // [time since start, expected number of POSTs]
    const checkpoints: Array<[number, number]> = [
      [FIRST_FIRE_MS, 1],
      [FIRST_FIRE_MS + 5 * SECOND - 1, 1],
      [FIRST_FIRE_MS + 5 * SECOND, 2],
      [FIRST_FIRE_MS + 20 * SECOND - 1, 2],
      [FIRST_FIRE_MS + 20 * SECOND, 3],
      [FIRST_FIRE_MS + 65 * SECOND - 1, 3],
      [FIRST_FIRE_MS + 65 * SECOND, 4],
      [FIRST_FIRE_MS + 125 * SECOND - 1, 4],
      [FIRST_FIRE_MS + 125 * SECOND, 5],
      [FIRST_FIRE_MS + 185 * SECOND - 1, 5],
      [FIRST_FIRE_MS + 185 * SECOND, 6],
    ];
    let elapsed = 0;
    for (const [at, posts] of checkpoints) {
      await advance(at - elapsed);
      elapsed = at;
      expect(fetchMock()).toHaveBeenCalledTimes(posts);
    }
  });

  it('starts the backoff over after a success', async () => {
    fetchMock()
      .mockResolvedValueOnce({ ok: false, status: 500 }) // first cycle fails → retry in 5 s
      .mockResolvedValueOnce({ ok: true, status: 200 }) // retry succeeds
      .mockResolvedValueOnce({ ok: false, status: 500 }); // next cycle fails again
    start('session-1', jwtExpiringIn(900));

    await advance(FIRST_FIRE_MS + 5 * SECOND); // failure, then successful retry
    expect(fetchMock()).toHaveBeenCalledTimes(2);

    await advance(FIRST_FIRE_MS); // next cycle fires and fails
    expect(fetchMock()).toHaveBeenCalledTimes(3);

    // Counter was reset by the success: the retry comes after 5 s, not 15 s.
    await advance(5 * SECOND);
    expect(fetchMock()).toHaveBeenCalledTimes(4);
  });

  it('gives up 10 minutes after the last synced token expired, and a later ensure restarts', async () => {
    fetchMock().mockResolvedValue({ ok: false, status: 500 });
    start('session-1', jwtExpiringIn(900));

    await advance(2 * HOUR);
    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);

    const postsAtGiveUp = fetchMock().mock.calls.length;
    await advance(HOUR);
    expect(fetchMock()).toHaveBeenCalledTimes(postsAtGiveUp);

    start('session-1', jwtExpiringIn(900));
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
  });
});

// ─── Stopping and races ───────────────────────────────────────────────────────

describe('stopping a monitor', () => {
  it('cancels the pending timer', async () => {
    start();
    stopTokenRefreshMonitor('session-1');

    expect(isTokenRefreshMonitorActive('session-1')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);
    await advance(HOUR);
    expect(mockForceAuthRefresh).not.toHaveBeenCalled();
  });

  it('is a no-op for an unknown session', () => {
    expect(() => stopTokenRefreshMonitor('nope')).not.toThrow();
  });

  it('stopAll stops every session', () => {
    start('a');
    start('b');
    stopAllTokenRefreshMonitors();
    expect(isTokenRefreshMonitorActive('a')).toBe(false);
    expect(isTokenRefreshMonitorActive('b')).toBe(false);
    expect(jest.getTimerCount()).toBe(0);
  });

  it('does not send the POST if stopped while forceAuthRefresh is in flight', async () => {
    const refresh = deferred<{ access_token: string }>();
    mockForceAuthRefresh.mockReturnValueOnce(refresh.promise);
    start();
    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);

    stopTokenRefreshMonitor('session-1');
    refresh.resolve({ access_token: jwtExpiringIn(900) });
    await advance(0);

    expect(fetchMock()).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
  });

  it('aborts the in-flight request when stopped, without retrying or logging an error', async () => {
    fetchMock().mockImplementation(
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        })
    );
    start();
    await advance(FIRST_FIRE_MS);
    expect(fetchMock()).toHaveBeenCalledTimes(1);
    const signal = fetchMock().mock.calls[0][1].signal as AbortSignal;

    stopTokenRefreshMonitor('session-1');
    await advance(0);

    expect(signal.aborted).toBe(true);
    expect(console.error).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
    await advance(HOUR);
    expect(fetchMock()).toHaveBeenCalledTimes(1);
  });
});

describe('races between an in-flight refresh and a newer monitor', () => {
  it('a stale monitor that was stopped mid-forceAuthRefresh cannot affect the replacement', async () => {
    const refresh = deferred<{ access_token: string }>();
    mockForceAuthRefresh.mockReturnValueOnce(refresh.promise);
    start('session-1', jwtExpiringIn(900)); // monitor A
    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1); // A is mid-refresh

    stopTokenRefreshMonitor('session-1');
    start('session-1', jwtExpiringIn(900)); // monitor B, same session

    refresh.resolve({ access_token: jwtExpiringIn(900) }); // A resumes
    await advance(0);

    expect(fetchMock()).not.toHaveBeenCalled(); // A is stale: no POST
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true); // B untouched

    await advance(FIRST_FIRE_MS); // B fires on its own schedule
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
    expect(fetchMock()).toHaveBeenCalledTimes(1);
  });

  it('a stale monitor whose request fails with 404 cannot delete the replacement (the orphaned-timer bug)', async () => {
    const response = deferred<{ ok: boolean; status: number }>();
    fetchMock().mockReturnValueOnce(response.promise);
    start('session-1', jwtExpiringIn(900)); // monitor A
    await advance(FIRST_FIRE_MS);
    expect(fetchMock()).toHaveBeenCalledTimes(1); // A's POST is in flight

    stopTokenRefreshMonitor('session-1');
    start('session-1', jwtExpiringIn(900)); // monitor B

    response.resolve({ ok: false, status: 404 }); // A's late answer
    await advance(0);

    // B must still be registered AND still have its timer: no orphan, no lost monitor.
    expect(isTokenRefreshMonitorActive('session-1')).toBe(true);
    expect(jest.getTimerCount()).toBe(1);

    await advance(FIRST_FIRE_MS);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
  });

  it('a stale monitor that succeeds late does not reschedule over the replacement', async () => {
    const response = deferred<{ ok: boolean; status: number }>();
    fetchMock().mockReturnValueOnce(response.promise);
    start('session-1', jwtExpiringIn(900)); // monitor A
    await advance(FIRST_FIRE_MS);

    stopTokenRefreshMonitor('session-1');
    start('session-1', jwtExpiringIn(900)); // monitor B

    response.resolve({ ok: true, status: 200 }); // A's late success
    await advance(0);

    expect(jest.getTimerCount()).toBe(1); // only B's timer, A did not arm another
  });

  it('ensure during an in-flight refresh is a no-op: one POST, one next cycle', async () => {
    const response = deferred<{ ok: boolean; status: number }>();
    fetchMock().mockReturnValueOnce(response.promise);
    start('session-1', jwtExpiringIn(900));
    await advance(FIRST_FIRE_MS);
    expect(fetchMock()).toHaveBeenCalledTimes(1);

    start('session-1', jwtExpiringIn(900)); // e.g. a follow-up submit
    start('session-1', jwtExpiringIn(900));
    expect(jest.getTimerCount()).toBe(0); // nothing new armed while the request is in flight

    response.resolve({ ok: true, status: 200 });
    await advance(0);
    expect(jest.getTimerCount()).toBe(1);

    await advance(FIRST_FIRE_MS - 1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
    expect(fetchMock()).toHaveBeenCalledTimes(2);
  });
});
