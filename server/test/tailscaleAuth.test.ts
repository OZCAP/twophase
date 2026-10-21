import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Request } from 'express';
import { tailnetCallerIp, type TailscaleIdentity } from '../src/tailscaleAuth.js';
import { startProxy } from './helpers.js';

const DEVICES: Record<string, TailscaleIdentity> = {
  '100.0.0.1': { ip: '100.0.0.1', node: 'iphone', tags: ['tag:admin-client'], login: null },
  '100.0.0.2': { ip: '100.0.0.2', node: 'staging', tags: ['tag:admin-accessible'], login: null },
  '100.0.0.3': { ip: '100.0.0.3', node: 'laptop', tags: [], login: 'alice@github' },
};

describe('tailnetCallerIp', () => {
  it('ignores forwarded identities from a non-loopback connection', () => {
    const request = {
      socket: { remoteAddress: '198.51.100.1' },
      header: () => '100.0.0.1',
    } as unknown as Request;
    expect(tailnetCallerIp(request)).toBeNull();
  });
});

describe('ADMIN_AUTH=tailscale', () => {
  let proxy: Awaited<ReturnType<typeof startProxy>>;
  const as = (ip: string | null, path = '/status', init: RequestInit = {}) =>
    fetch(`${proxy.base}/admin/api${path}`, { ...init, headers: { ...(ip && { 'x-forwarded-for': ip }), ...init.headers } });

  beforeAll(async () => {
    proxy = await startProxy(
      { adminAuth: 'tailscale' },
      {
        whois: async (ip) => {
          if (ip === '100.0.0.4') throw new Error('tailscaled unavailable');
          return DEVICES[ip] ?? null;
        },
      },
    );
  });
  afterAll(async () => proxy?.close());

  it.each(Object.values(DEVICES))('lets $node manage the proxy without a token and reports its identity', async (device) => {
    const res = await as(device.ip);
    expect(res.status).toBe(200);
    expect((await res.json()).auth).toEqual({ mode: 'tailscale', device: device.node, login: device.login });
    const created = await as(device.ip, '/users', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: `Created by ${device.node}` }),
    });
    expect(created.status).toBe(201);
  });

  it('rejects requests when the device identity cannot be verified', async () => {
    expect((await as('100.0.0.4')).status).toBe(401);
  });

  it('rejects requests without a tailnet identity, and ignores the old admin token', async () => {
    expect((await as(null)).status).toBe(401);
    expect((await as('8.8.8.8')).status).toBe(401);
    expect((await as(null, '/status', { headers: { authorization: 'Bearer test-admin-token' } })).status).toBe(401);
    expect((await as(null, '/status', { headers: { 'tailscale-user-login': 'alice@github' } })).status).toBe(401);
  });

  it('refuses to start unless bound to loopback', async () => {
    await expect(startProxy({ adminAuth: 'tailscale', host: '0.0.0.0' })).rejects.toThrow(/HOST=127.0.0.1/);
  });
});
