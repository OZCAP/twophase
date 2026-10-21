import { afterEach, describe, expect, it, vi } from 'vitest';
import { detectAuth } from './auth';
import { Api } from './api';

afterEach(() => vi.unstubAllGlobals());
function responses(...values: { status?: number; body: unknown }[]) {
  const mock = vi.fn();
  for (const { status = 200, body } of values) mock.mockResolvedValueOnce(new Response(JSON.stringify(body), { status }));
  vi.stubGlobal('fetch', mock);
  return mock;
}
describe('management sign-in', () => {
  it.each(['password', 'tailscale'] as const)('requires password sign-in in %s mode and ignores old saved tokens', async (mode) => {
    const fetch = responses({ body: { mode, passwordRequired: true } }, { status: 401, body: { error: 'Sign in', code: 'password_required' } });
    expect(await detectAuth('obsolete-example-token')).toEqual({ state: 'login', info: { mode, passwordRequired: true } });
    expect(fetch.mock.calls[1][1].headers.authorization).toBeUndefined();
  });
  it('recognizes an existing cookie session without prompting', async () => {
    responses({ body: { mode: 'password', passwordRequired: true } }, { body: { auth: { mode: 'password' } } });
    expect(await detectAuth(null)).toMatchObject({ state: 'ready', token: '' });
  });
  it('preserves token login and Tailscale automatic sign-in when no password is configured', async () => {
    const fetch = responses({ body: { mode: 'token', passwordRequired: false } }, { body: { auth: { mode: 'token' } } });
    expect(await detectAuth('dummy-admin-token')).toMatchObject({ state: 'ready', token: 'dummy-admin-token' });
    expect(fetch.mock.calls[1][1].headers.authorization).toBe('Bearer dummy-admin-token');
    responses({ body: { mode: 'tailscale', passwordRequired: false } }, { body: { auth: { mode: 'tailscale' } } });
    expect(await detectAuth(null)).toMatchObject({ state: 'ready', token: '' });
  });
  it('reports missing Tailscale identity instead of offering a password bypass', async () => {
    responses({ body: { mode: 'tailscale', passwordRequired: true } }, { status: 401, body: { error: 'Open through Tailscale', code: 'tailscale_required' } });
    expect(await detectAuth(null)).toEqual({ state: 'blocked', message: 'Open through Tailscale' });
  });
  it('sends the password only to the login endpoint and uses same-origin cookies', async () => {
    const fetch = responses({ body: {} });
    await new Api('').login('example-only-password');
    expect(fetch).toHaveBeenCalledWith('/admin/api/login', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', body: JSON.stringify({ password: 'example-only-password' }),
    }));
  });
});
