import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { startProxy, type TestProxy } from './helpers.js';

const PASSWORD = 'example-only-management-password';
const proxies: TestProxy[] = [];
const directories: string[] = [];
const cookieOf = (response: Response) => response.headers.get('set-cookie')!.split(';')[0];
const identity = { ip: '100.64.0.1', node: 'fixture-laptop', tags: [], login: 'alice@example.com' };
const json = (password = PASSWORD): RequestInit => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password }) });
async function proxy(tailscale = false) {
  const p = await startProxy({ adminPassword: PASSWORD, adminAuth: tailscale ? 'tailscale' : 'token' }, {
    whois: async (ip) => ip === identity.ip ? identity : ip === '100.64.0.2' ? { ...identity, ip, node: 'other-fixture-device' } : null,
  });
  proxies.push(p);
  return p;
}
afterEach(async () => {
  vi.useRealTimers();
  for (const p of proxies.splice(0)) await p.close();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe('management password', () => {
  it('requires a password for every management API entry point, including SSE', async () => {
    const p = await proxy();
    expect(await (await fetch(`${p.base}/admin/api/auth`)).json()).toEqual({ mode: 'password', passwordRequired: true });
    for (const path of ['/status', '/databases', '/users', '/approvals', '/audit', '/events', '/push/config']) {
      const response = await fetch(`${p.base}/admin/api${path}`, { headers: { authorization: 'Bearer test-admin-token' } });
      expect(response.status).toBe(401);
      expect((await response.json()).code).toBe('password_required');
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
    expect((await fetch(`${p.base}/healthz`)).status).toBe(200);
    const wrong = await fetch(`${p.base}/admin/api/login`, json('wrong-example-password'));
    expect(wrong.status).toBe(401);
    expect(wrong.headers.get('set-cookie')).toBeNull();
    const login = await fetch(`${p.base}/admin/api/login`, json());
    expect(login.status).toBe(204);
    expect(login.headers.get('set-cookie')).toContain('HttpOnly');
    expect(login.headers.get('set-cookie')).toContain('SameSite=Strict');
    expect(login.headers.get('set-cookie')).toContain('Path=/admin/api');
    expect(login.headers.get('set-cookie')).toContain('Max-Age=2592000');
    const cookie = cookieOf(login);
    expect(cookie).not.toContain(PASSWORD);
    const status = await fetch(`${p.base}/admin/api/status`, { headers: { cookie } });
    expect(status.status).toBe(200);
    expect((await status.json()).auth).toMatchObject({ mode: 'password', passwordRequired: true });
    expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie: `${cookie}tampered` } })).status).toBe(401);
    const logout = await fetch(`${p.base}/admin/api/logout`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' } });
    expect(logout.status).toBe(204);
    expect(logout.headers.get('set-cookie')).toContain('Max-Age=0');
    expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie } })).status).toBe(401);
  });

  it('requires both a verified Tailscale identity and a password, and binds sessions to the device', async () => {
    const p = await proxy(true);
    expect((await fetch(`${p.base}/admin/api/login`, json())).status).toBe(401);
    const headers = { 'content-type': 'application/json', 'x-forwarded-for': identity.ip, 'x-forwarded-proto': 'https' };
    const login = await fetch(`${p.base}/admin/api/login`, { ...json(), headers });
    expect(login.status).toBe(204);
    expect(login.headers.get('set-cookie')).toContain('Secure');
    const cookie = cookieOf(login);
    const response = await fetch(`${p.base}/admin/api/status`, { headers: { ...headers, cookie } });
    expect(response.status).toBe(200);
    expect((await response.json()).auth).toMatchObject({ mode: 'tailscale', device: identity.node, passwordRequired: true });
    expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie } })).status).toBe(401);
    expect((await fetch(`${p.base}/admin/api/status`, { headers })).status).toBe(401);
    expect((await fetch(`${p.base}/admin/api/status`, { headers: { ...headers, cookie, 'x-forwarded-for': '100.64.0.2' } })).status).toBe(401);
  });

  it('rejects cross-site login and management requests', async () => {
    const p = await proxy();
    const login = await fetch(`${p.base}/admin/api/login`, json());
    const cookie = cookieOf(login);
    const hostile = { origin: 'https://other.example.com', 'sec-fetch-site': 'cross-site', 'content-type': 'application/json', cookie };
    expect((await fetch(`${p.base}/admin/api/login`, { ...json(), headers: hostile })).status).toBe(403);
    expect((await fetch(`${p.base}/admin/api/users`, { method: 'POST', headers: hostile, body: JSON.stringify({ name: 'blocked' }) })).status).toBe(403);
    expect((await fetch(`${p.base}/admin/api/users`, { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, body: 'name=blocked' })).status).toBe(403);
    const allowed = await fetch(`${p.base}/admin/api/users`, { method: 'POST', headers: { cookie, origin: p.base, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'fixture-client' }) });
    expect(allowed.status).toBe(201);
  });

  it('marks network-host cookies Secure even when a TLS proxy does not forward its scheme', async () => {
    const p = await proxy();
    // Fetch controls Host itself; use HTTP directly to emulate a reverse proxy preserving Host.
    const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const request = http.request(`${p.base}/admin/api/login`, { method: 'POST', headers: { 'content-type': 'application/json', host: 'management.example.com' } }, (response) => { response.resume(); resolve(response); });
      request.once('error', reject);
      request.end(JSON.stringify({ password: PASSWORD }));
    });
    expect(response.statusCode).toBe(204);
    expect(response.headers['set-cookie']?.[0]).toContain('Secure');
  });

  it('limits incorrect password attempts per caller', async () => {
    const p = await proxy();
    for (let n = 0; n < 5; n++) expect((await fetch(`${p.base}/admin/api/login`, json('wrong-example-password'))).status).toBe(401);
    const blocked = await fetch(`${p.base}/admin/api/login`, json());
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBe('60');
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 61_000);
    try { expect((await fetch(`${p.base}/admin/api/login`, json())).status).toBe(204); }
    finally { vi.restoreAllMocks(); }
  });

  it('closes event streams on logout and rejects expired sessions', async () => {
    const p = await proxy();
    const login = await fetch(`${p.base}/admin/api/login`, json());
    const cookie = cookieOf(login);
    const stream = await fetch(`${p.base}/admin/api/events`, { headers: { cookie } });
    const reader = stream.body!.getReader();
    await reader.read();
    const finished = reader.read();
    await fetch(`${p.base}/admin/api/logout`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' } });
    expect((await finished).done).toBe(true);
    const second = await fetch(`${p.base}/admin/api/login`, json());
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 31 * 24 * 60 * 60_000);
    try { expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie: cookieOf(second) } })).status).toBe(401); }
    finally { vi.restoreAllMocks(); }
  });

  it('remembers the browser on later days without retaining the password in the cookie', async () => {
    const p = await proxy();
    const login = await fetch(`${p.base}/admin/api/login`, json());
    const cookie = cookieOf(login);
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now');
    try {
      clock.mockReturnValue(now + 29 * 24 * 60 * 60_000);
      expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie } })).status).toBe(200);
      clock.mockReturnValue(now + 31 * 24 * 60 * 60_000);
      expect((await fetch(`${p.base}/admin/api/status`, { headers: { cookie } })).status).toBe(401);
      expect(cookie).not.toContain(PASSWORD);
    } finally { clock.mockRestore(); }
  });

  it('preserves sessions across restarts, stores only hashes, and revokes them when the password changes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'twophase-password-'));
    directories.push(directory);
    const config = { ...loadConfig({}), host: '127.0.0.1', port: 0, dataDir: directory, adminPassword: PASSWORD,
      wire: { enabled: false, host: '127.0.0.1', port: 0, publicPort: 0 }, mysqlWire: { enabled: false, host: '127.0.0.1', port: 0, publicPort: 0 } };
    const first = createApp(config);
    const firstPort = (await first.listen()).httpPort;
    const cookie = cookieOf(await fetch(`http://127.0.0.1:${firstPort}/admin/api/login`, json()));
    expect(first.store.getSetting('admin_password_sessions')).not.toContain(cookie.split('=')[1]);
    expect(first.store.getSetting('admin_password_verifier')).not.toContain(PASSWORD);
    await first.close();
    for (const password of [PASSWORD, 'different-example-only-password']) {
      const app = createApp({ ...config, adminPassword: password });
      try {
        const port = (await app.listen()).httpPort;
        expect((await fetch(`http://127.0.0.1:${port}/admin/api/status`, { headers: { cookie } })).status).toBe(password === PASSWORD ? 200 : 401);
      } finally { await app.close(); }
    }
  });

  it('ends event streams when their password session expires', async () => {
    const p = await proxy();
    const login = await fetch(`${p.base}/admin/api/login`, json());
    const cookie = cookieOf(login);
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    const stream = await fetch(`${p.base}/admin/api/events`, { headers: { cookie } });
    const reader = stream.body!.getReader();
    await reader.read();
    const finished = reader.read();
    await vi.advanceTimersByTimeAsync(30 * 24 * 60 * 60_000);
    expect((await finished).done).toBe(true);
  });

  it('supports password files without committing a password to configuration', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'twophase-password-file-'));
    directories.push(directory);
    const file = join(directory, 'password');
    await writeFile(file, `${PASSWORD}\n`, { mode: 0o600 });
    expect(loadConfig({ ADMIN_PASSWORD_FILE: file }).adminPassword).toBe(PASSWORD);
    expect(() => loadConfig({ ADMIN_PASSWORD: PASSWORD, ADMIN_PASSWORD_FILE: file })).toThrow('Set only one');
    await writeFile(file, '');
    expect(() => loadConfig({ ADMIN_PASSWORD_FILE: file })).toThrow('must contain a password');
    expect(() => loadConfig({ ADMIN_PASSWORD_FILE: join(directory, 'missing') })).toThrow();
  });
});
