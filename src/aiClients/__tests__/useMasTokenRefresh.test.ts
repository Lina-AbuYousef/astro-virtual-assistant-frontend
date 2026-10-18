import {
  getTokenExpMs,
  scheduleTokenRefresh,
  activeRefreshTimers,
  ChromeAuth,
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

/** JWT whose exp is `offsetSeconds` from now. */
function jwtExpiringIn(offsetSeconds: number): string {
  return makeJwt(Math.floor(Date.now() / 1000) + offsetSeconds);
}

// ─── Mock chrome ─────────────────────────────────────────────────────────────

const mockForceAuthRefresh = jest.fn();

const mockChrome: ChromeAuth = {
  $internal: {
    forceAuthRefresh: mockForceAuthRefresh,
  },
};

const BASE_URL = 'https://mas.example.com';

// ─── Setup / teardown ────────────────────────────────────────────────────────

beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
  activeRefreshTimers.clear();

  // Default: forceAuthRefresh returns a fresh token
  mockForceAuthRefresh.mockResolvedValue({ access_token: 'refreshed-token' });

  // Default: token-refresh endpoint returns 200
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
});

afterEach(() => {
  jest.useRealTimers();
  activeRefreshTimers.forEach((id) => clearTimeout(id));
  activeRefreshTimers.clear();
});

// ─── getTokenExpMs ────────────────────────────────────────────────────────────

describe('getTokenExpMs', () => {
  it('returns exp in milliseconds for a valid JWT', () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 900; // 15 min from now
    const token = makeJwt(expSeconds);
    expect(getTokenExpMs(token)).toBe(expSeconds * 1000);
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
    const payload = btoa(JSON.stringify({ sub: 'user-1' })); // no exp
    expect(getTokenExpMs(`${header}.${payload}.sig`)).toBeNull();
  });

  it('returns null when exp is not a number', () => {
    const header = btoa(JSON.stringify({ alg: 'RS256' }));
    const payload = btoa(JSON.stringify({ exp: 'not-a-number' }));
    expect(getTokenExpMs(`${header}.${payload}.sig`)).toBeNull();
  });

  it('handles base64url encoding (- and _ characters)', () => {
    // Construct a payload that, when base64-encoded, contains + or /
    // by using a sub with characters that shift the base64 output.
    const expSeconds = 9999999999;
    const token = makeJwt(expSeconds);
    expect(getTokenExpMs(token)).toBe(expSeconds * 1000);
  });
});

// ─── scheduleTokenRefresh ─────────────────────────────────────────────────────

describe('scheduleTokenRefresh', () => {
  it('registers a timer in activeRefreshTimers', async () => {
    const token = jwtExpiringIn(900); // 15 min
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);
    expect(activeRefreshTimers.has('session-1')).toBe(true);
  });

  it('does not start a monitor when the JWT has no exp claim', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    await scheduleTokenRefresh('session-1', 'bad.token.here', BASE_URL, mockChrome);
    expect(activeRefreshTimers.has('session-1')).toBe(false);
    consoleSpy.mockRestore();
  });

  it('replaces an existing timer for the same session', async () => {
    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);
    const firstTimerId = activeRefreshTimers.get('session-1');

    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);
    const secondTimerId = activeRefreshTimers.get('session-1');

    expect(secondTimerId).not.toBe(firstTimerId);
  });

  it('fires 2 minutes before token expiry', async () => {
    // Pin the clock to a whole second so Math.floor(Date.now()/1000) has
    // no fractional-ms remainder and the delay is exactly 780 000 ms.
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const token = jwtExpiringIn(900); // exp = T+900s; timer should fire at T+780s
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    // One ms before the 13-min mark — should NOT have fired
    jest.advanceTimersByTime(780_000 - 1);
    expect(mockForceAuthRefresh).not.toHaveBeenCalled();

    // Exactly at the 13-min mark (15 min − 2 min buffer) — should fire
    jest.advanceTimersByTime(1);
    await Promise.resolve();
    await Promise.resolve();
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });

  it('fires immediately when token is already within the 2-minute buffer', async () => {
    const token = jwtExpiringIn(60); // expires in 1 min — already inside 2-min buffer
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(0);
    await Promise.resolve();
    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(1);
  });

  it('POSTs the new token to the correct endpoint with correct body', async () => {
    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve(); // flush async fetch

    expect(global.fetch).toHaveBeenCalledWith(
      `${BASE_URL}/api/sessions/session.token-refresh`,
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Authorization: 'Bearer refreshed-token',
        }),
        body: JSON.stringify({ sessionId: 'session-1', token: 'refreshed-token' }),
      })
    );
  });

  it('stops the monitor when forceAuthRefresh returns no token', async () => {
    mockForceAuthRefresh.mockResolvedValue(null);
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(global.fetch).not.toHaveBeenCalled();
    expect(activeRefreshTimers.has('session-1')).toBe(false);
    consoleSpy.mockRestore();
  });

  it('stops the monitor when the backend returns 404 (session ended)', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 404 });

    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(activeRefreshTimers.has('session-1')).toBe(false);
    // Should not reschedule — fetch called exactly once
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('stops the monitor when the backend returns a non-ok non-404 status', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 500 });
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(activeRefreshTimers.has('session-1')).toBe(false);
    consoleSpy.mockRestore();
  });

  it('reschedules with the new token after a successful refresh', async () => {
    const firstToken = jwtExpiringIn(900);     // expires in 15 min
    const secondToken = jwtExpiringIn(1800);   // new token: expires in 30 min
    mockForceAuthRefresh.mockResolvedValue({ access_token: secondToken });

    await scheduleTokenRefresh('session-1', firstToken, BASE_URL, mockChrome);

    // First refresh fires at 13 min
    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    // A new timer should be registered for the second token
    expect(activeRefreshTimers.has('session-1')).toBe(true);

    // Second refresh should fire 28 min from now (30 min - 2 min buffer)
    jest.advanceTimersByTime(28 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(mockForceAuthRefresh).toHaveBeenCalledTimes(2);
  });

  it('stops the monitor and logs an error when forceAuthRefresh throws', async () => {
    mockForceAuthRefresh.mockRejectedValue(new Error('SSO network failure'));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(activeRefreshTimers.has('session-1')).toBe(false);
    expect(consoleSpy).toHaveBeenCalledWith(
      '[MAS token-refresh] unexpected error — stopping monitor',
      expect.any(Error)
    );
    consoleSpy.mockRestore();
  });

  it('stops the monitor and logs an error when fetch throws', async () => {
    (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const token = jwtExpiringIn(900);
    await scheduleTokenRefresh('session-1', token, BASE_URL, mockChrome);

    jest.advanceTimersByTime(13 * 60 * 1000);
    await Promise.resolve();
    await Promise.resolve();

    expect(activeRefreshTimers.has('session-1')).toBe(false);
    consoleSpy.mockRestore();
  });

  it('handles multiple sessions independently', async () => {
    const tokenA = jwtExpiringIn(900);
    const tokenB = jwtExpiringIn(600);

    await scheduleTokenRefresh('session-A', tokenA, BASE_URL, mockChrome);
    await scheduleTokenRefresh('session-B', tokenB, BASE_URL, mockChrome);

    expect(activeRefreshTimers.has('session-A')).toBe(true);
    expect(activeRefreshTimers.has('session-B')).toBe(true);
    expect(activeRefreshTimers.get('session-A')).not.toBe(activeRefreshTimers.get('session-B'));
  });
});
