import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';
import tls from 'node:tls';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import mysql from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { databaseStream, isTailnetHost, openDatabaseSocket } from '../src/databaseSocket.js';
import { createTestDatabase, PG_ADMIN_URL, postgresAvailable, startProxy, type TestProxy } from './helpers.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql, type Flavour } from './mysql-helpers.js';

const pgAvailable = await postgresAvailable();
const flavours: Flavour[] = ['mysql', 'mariadb'];
const available = Object.fromEntries(await Promise.all(flavours.map(async (f) => [f, await mysqlAvailable(f)])));
const host = 'fixture.example.ts.net';
let directory: string;
let server: http.Server;
const sockets = new Set<net.Socket>();
const dials: { host: string; port: number }[] = [];
const track = (socket: net.Socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); return socket; };

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'twophase-dial-'));
  server = http.createServer((request, response) => {
    expect(request.url).toBe('/localapi/v0/status');
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ Peer: { fixture: { HostName: 'different-os-hostname', DNSName: `${host}.` } } }));
  });
  server.on('upgrade', (request, raw) => {
    const socket = track(raw as net.Socket);
    const destination = String(request.headers['dial-host']);
    const port = Number(request.headers['dial-port']);
    dials.push({ host: destination, port });
    expect(request.url).toBe('/localapi/v0/dial');
    if (destination === 'denied.example.ts.net') {
      socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    if (destination === 'stall.example.ts.net') return;
    if (destination === 'greeting.example.ts.net') {
      socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ts-dial\r\n\r\nhello');
      socket.pipe(socket);
      return;
    }
    // The fake LocalAPI resolves an otherwise unresolvable tailnet hostname to a disposable fixture.
    const upstream = track(net.connect({ host: '127.0.0.1', port }));
    upstream.once('error', () => socket.destroy());
    socket.once('error', () => upstream.destroy());
    socket.once('close', () => upstream.destroy());
    upstream.once('connect', () => {
      socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ts-dial\r\n\r\n');
      socket.pipe(upstream).pipe(socket);
    });
  });
  await new Promise<void>((resolve) => server.listen(join(directory, 'tailscaled.sock'), resolve));
  vi.stubEnv('TAILSCALE_SOCKET', join(directory, 'tailscaled.sock'));
});
afterAll(async () => {
  vi.unstubAllEnvs();
  for (const socket of sockets) socket.destroy();
  if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  if (directory) await rm(directory, { recursive: true, force: true });
});

it('selects only full tailnet DNS names and Tailscale IP ranges', () => {
  for (const name of [host, 'EXAMPLE.TS.NET.', '100.64.0.1', '100.127.255.255', 'fd7a:115c:a1e0::1']) expect(isTailnetHost(name)).toBe(true);
  for (const name of ['localhost', 'example.com', 'example.ts.net.attacker.com', '100.63.255.255', '100.128.0.0', 'fd7a:115c:a1e1::1']) expect(isTailnetHost(name)).toBe(false);
  expect(databaseStream('127.0.0.1', 5432)).toBeUndefined();
  const path = process.env.TAILSCALE_SOCKET!;
  vi.stubEnv('TAILSCALE_SOCKET', '');
  expect(databaseStream(host, 5432)).toBeUndefined();
  vi.stubEnv('TAILSCALE_SOCKET', path);
});

it('preserves server greetings received alongside the HTTP upgrade', async () => {
  const socket = await openDatabaseSocket('greeting.example.ts.net', 5432);
  try {
    const received = once(socket, 'data');
    socket.resume();
    expect((await received)[0].toString()).toBe('hello');
    socket.write('echo');
    expect((await once(socket, 'data'))[0].toString()).toBe('echo');
  } finally { socket.destroy(); }
});

it('reports refused dials without falling back to host networking', async () => {
  await expect(openDatabaseSocket('denied.example.ts.net', 5432)).rejects.toThrow('HTTP 403');
  const stream = databaseStream('denied.example.ts.net', 5432)!();
  const [error] = await once(stream, 'error');
  expect(error.message).toContain('HTTP 403');
  expect(stream.destroyed).toBe(true);
});

it('cancels pending dials when the driver destroys its stream', async () => {
  const stream = databaseStream('stall.example.ts.net', 5432)!();
  const closed = once(stream, 'close');
  await new Promise((resolve) => setTimeout(resolve, 20));
  stream.destroy();
  await closed;
  expect(stream.destroyed).toBe(true);
});

it('bounds stalled LocalAPI dials and closes their streams', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    const requestArrived = once(server, 'upgrade');
    const stream = databaseStream('stall.example.ts.net', 5432)!();
    const failed = once(stream, 'error');
    await requestArrived;
    await vi.advanceTimersByTimeAsync(10_000);
    expect((await failed)[0].message).toContain('timed out');
    expect(stream.destroyed).toBe(true);
  } finally { vi.useRealTimers(); }
});

it('keeps ordinary database connections on the native network', async () => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
  const before = dials.length;
  const socket = await openDatabaseSocket('127.0.0.1', (echo.address() as net.AddressInfo).port);
  try {
    const received = once(socket, 'data');
    socket.write('native');
    expect((await received)[0].toString()).toBe('native');
    expect(dials.length).toBe(before);
  } finally { socket.destroy(); await new Promise<void>((resolve) => echo.close(() => resolve())); }
});

it('routes short MagicDNS names through the sidecar for both raw sockets and driver streams', async () => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
  const port = (echo.address() as net.AddressInfo).port;
  const raw = await openDatabaseSocket('FIXTURE', port);
  const stream = databaseStream('fixture', port)!();
  try {
    for (const socket of [raw, stream]) {
      const received = once(socket, 'data');
      socket.resume();
      socket.write('short-name');
      expect((await received)[0].toString()).toBe('short-name');
    }
    expect(dials.slice(-2)).toEqual([{ host, port }, { host, port }]);
  } finally {
    raw.destroy(); stream.destroy();
    await new Promise<void>((resolve) => echo.close(() => resolve()));
  }
});

it('preserves native DNS for short names absent from the tailnet', async () => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
  const lookup = vi.spyOn(dns, 'lookup').mockImplementation(((name: string, _options: dns.LookupAllOptions, callback: (error: null, addresses: dns.LookupAddress[]) => void) => {
    expect(name).toBe('fixture-local');
    callback(null, [{ address: '127.0.0.1', family: 4 }]);
  }) as typeof dns.lookup);
  const before = dials.length;
  try {
    const socket = await openDatabaseSocket('fixture-local', (echo.address() as net.AddressInfo).port);
    const received = once(socket, 'data');
    socket.write('native');
    expect((await received)[0].toString()).toBe('native');
    socket.destroy();
    expect(dials.length).toBe(before);
    expect(lookup).toHaveBeenCalled();
  } finally {
    lookup.mockRestore();
    await new Promise<void>((resolve) => echo.close(() => resolve()));
  }
});

it('retains TLS certificate and hostname verification over driver streams', async () => {
  const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`], { stdio: 'ignore' });
  const cert = await readFile(certPath);
  const echo = tls.createServer({ key: await readFile(keyPath), cert }, (socket) => socket.pipe(socket));
  echo.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
  const port = (echo.address() as net.AddressInfo).port;
  try {
    const stream = databaseStream(host, port)!();
    const secure = tls.connect({ socket: stream, servername: host, ca: cert });
    await once(secure, 'secureConnect');
    const received = once(secure, 'data');
    secure.write('encrypted');
    expect((await received)[0].toString()).toBe('encrypted');
    secure.destroy();
    const wrong = tls.connect({ socket: databaseStream(host, port)!(), servername: 'wrong.example.ts.net', ca: cert });
    const [error] = await once(wrong, 'error');
    expect(error.code).toBe('ERR_TLS_CERT_ALTNAME_INVALID');
    wrong.destroy();
  } finally { await new Promise<void>((resolve) => echo.close(() => resolve())); }
});

describe.skipIf(!pgAvailable)('PostgreSQL through userspace Tailscale', () => {
  it('uses the sidecar for connection tests, MCP pools, TLS prefer probes, and wire sessions', async () => {
    const db = await createTestDatabase();
    let proxy: TestProxy | undefined;
    let agent: Awaited<ReturnType<TestProxy['mcp']>> | undefined;
    try {
      proxy = await startProxy();
      const seeded = await proxy.seed(db);
      await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { host: 'fixture', sslmode: 'prefer' });
      expect(await proxy.admin('POST', `/databases/${seeded.db.id}/test`)).toMatchObject({ ok: true });
      agent = await proxy.mcp(seeded.client.token, 'shop');
      expect((await agent.callTool({ name: 'query', arguments: { sql: 'SELECT 42 AS n' } })).isError).toBeFalsy();
      const wire = await proxy.wire(seeded.client.user.username, seeded.client.token, 'shop');
      try { expect((await wire.query('SELECT 42 AS n')).rows).toEqual([{ n: 42 }]); }
      finally { await wire.end(); }
      expect(dials).toContainEqual({ host, port: Number(new URL(PG_ADMIN_URL).port) });
    } finally { await agent?.close(); await proxy?.close(); await db.drop(); }
  });
});

for (const flavour of flavours) describe.skipIf(!available[flavour])(`${flavour} through userspace Tailscale`, () => {
  it('uses the sidecar for connection tests, MCP pools, TLS prefer probes, and wire sessions', async () => {
    const db = await createMysqlTestDatabase(flavour);
    let proxy: TestProxy | undefined;
    let agent: Awaited<ReturnType<TestProxy['mcp']>> | undefined;
    try {
      proxy = await startProxy();
      const seeded = await seedMysql(proxy, db);
      await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { host: 'fixture', sslmode: 'prefer' });
      expect(await proxy.admin('POST', `/databases/${seeded.db.id}/test`)).toMatchObject({ ok: true });
      agent = await proxy.mcp(seeded.client.token, 'shop');
      expect((await agent.callTool({ name: 'query', arguments: { sql: 'SELECT 42 AS n' } })).isError).toBeFalsy();
      const wire = await mysql.createConnection({ host: '127.0.0.1', port: proxy.mysqlWirePort,
        user: seeded.client.user.username, password: seeded.client.token, database: 'shop' });
      try { expect((await wire.query('SELECT 42 AS n'))[0]).toEqual([{ n: 42 }]); }
      finally { await wire.end(); }
      expect(dials).toContainEqual({ host, port: db.port });
    } finally { await agent?.close(); await proxy?.close(); await db.drop(); }
  });
});
