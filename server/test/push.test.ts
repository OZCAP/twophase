import { createECDH, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createRequire } from 'node:module';
import webpush from 'web-push';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import mysql from 'mysql2/promise';
import { createTestDatabase, postgresAvailable, startProxy, type TestDatabase } from './helpers.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql } from './mysql-helpers.js';

const ece = createRequire(import.meta.url)('http_ece') as {
  decrypt(buf: Buffer, params: { version: string; privateKey: ReturnType<typeof createECDH>; authSecret: string }): Buffer;
};

interface Received {
  path: string;
  headers: IncomingMessage['headers'];
  body: Buffer;
}

/**
 * Stands in for FCM / Mozilla autopush / Apple's push service: records each request and
 * answers with whatever status the test set for that path.
 */
function fakePushService() {
  const received: Received[] = [];
  const statusFor = new Map<string, number>();
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      received.push({ path: req.url!, headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(statusFor.get(req.url!) ?? 201).end();
    });
  });
  return { server, received, statusFor };
}

/** What a browser does in pushManager.subscribe(): an ECDH P-256 key pair plus a 16-byte auth secret. */
function browserSubscription(endpoint: string) {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const auth = randomBytes(16).toString('base64url');
  return {
    json: { endpoint, keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth } },
    decrypt: (body: Buffer) => JSON.parse(ece.decrypt(body, { version: 'aes128gcm', privateKey: ecdh, authSecret: auth }).toString()),
  };
}

const available = await postgresAvailable();
const vapid = webpush.generateVAPIDKeys();
let tdb: TestDatabase;
let proxy: Awaited<ReturnType<typeof startProxy>>;
let push: ReturnType<typeof fakePushService>;
let pushBase: string;
let clientToken: string;

beforeAll(async () => {
  push = fakePushService();
  await new Promise<void>((r) => push.server.listen(0, '127.0.0.1', r));
  pushBase = `http://127.0.0.1:${(push.server.address() as AddressInfo).port}`;
  proxy = await startProxy({
    vapid: { publicKey: vapid.publicKey, privateKey: vapid.privateKey, subject: 'mailto:ops@example.com' },
    approvalTimeoutSeconds: 30,
  });
  if (!available) return;
  tdb = await createTestDatabase();
  clientToken = (await proxy.seed(tdb)).client.token;
});

afterAll(async () => {
  await proxy?.close();
  push?.server.close();
  await tdb?.drop();
});

describe.skipIf(!available)('web push', () => {
  it('exposes the VAPID public key for pushManager.subscribe()', async () => {
    expect(await proxy.admin('GET', '/push/config')).toEqual({ vapidPublicKey: vapid.publicKey });
  });

  it('rejects non-https subscription endpoints', async () => {
    const sub = browserSubscription('http://evil.example.com/push');
    await expect(proxy.admin('POST', '/push/subscriptions', sub.json)).rejects.toThrow(/400/);
  });

  it('sends an encrypted, VAPID-signed notification when a call needs approval', async () => {
    const sub = browserSubscription(`${pushBase}/sub/phone`);
    await proxy.admin('POST', '/push/subscriptions', sub.json);

    const agent = await proxy.mcp(clientToken, 'shop');
    const call = agent.callTool({ name: 'query', arguments: { sql: "UPDATE orders SET status = 'paid' WHERE id = 1" } });
    const pending = await proxy.nextPending();

    await expect.poll(() => push.received.length).toBe(1);
    const msg = push.received[0];
    expect(msg.path).toBe('/sub/phone');
    expect(msg.headers['content-encoding']).toBe('aes128gcm');
    expect(msg.headers.urgency).toBe('high');
    expect(msg.headers.topic).toBe(pending.id.replaceAll('-', ''));
    expect(Number(msg.headers.ttl)).toBeGreaterThan(20);
    expect(msg.headers.authorization).toMatch(new RegExp(`^vapid t=[\\w-]+\\.[\\w-]+\\.[\\w-]+, k=${vapid.publicKey}$`));

    // The VAPID JWT must be scoped to the push service's origin.
    const jwt = msg.headers.authorization!.split(/t=|,/)[1];
    const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    expect(claims).toMatchObject({ aud: pushBase, sub: 'mailto:ops@example.com' });

    expect(sub.decrypt(msg.body)).toMatchObject({
      type: 'approval',
      approvalId: pending.id,
      title: 'Approve update on orders?',
      body: "agent via MCP → Shop\nUPDATE orders SET status = 'paid' WHERE id = 1",
      url: `/#/approvals/${pending.id}`,
    });

    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
    await call;
    await agent.close();
    await proxy.admin('DELETE', `/push/subscriptions?endpoint=${encodeURIComponent(sub.json.endpoint)}`);
  });

  it('drops subscriptions the push service reports as gone (410)', async () => {
    const live = browserSubscription(`${pushBase}/sub/live`);
    const gone = browserSubscription(`${pushBase}/sub/gone`);
    push.statusFor.set('/sub/gone', 410);
    await proxy.admin('POST', '/push/subscriptions', live.json);
    await proxy.admin('POST', '/push/subscriptions', gone.json);

    expect(await proxy.admin('POST', '/push/test')).toEqual({ sent: 1, failed: 0, removed: 1 });
    expect((await proxy.admin('GET', '/status')).webPushSubscriptions).toBe(1);

    const testMsg = push.received.find((r) => r.path === '/sub/live')!;
    expect(live.decrypt(testMsg.body)).toMatchObject({ type: 'message', title: 'Twophase' });
  });
});

describe.skipIf(!(await mysqlAvailable('mariadb')))('web push for MySQL-protocol clients', () => {
  it('names the engine and the client program in the notification', async () => {
    const mdb = await createMysqlTestDatabase('mariadb');
    const { client } = await seedMysql(proxy, mdb, 'maria');
    const sub = browserSubscription(`${pushBase}/sub/maria`);
    await proxy.admin('POST', '/push/subscriptions', sub.json);
    const c = await mysql.createConnection({ host: '127.0.0.1', port: proxy.mysqlWirePort, user: client.user.username, password: client.token, database: 'maria' });
    const run = c.query('DELETE FROM orders WHERE id = 1');
    const pending = await proxy.nextPending();
    await expect.poll(() => push.received.filter((r) => r.path === '/sub/maria').length).toBe(1);
    const msg = sub.decrypt(push.received.find((r) => r.path === '/sub/maria')!.body);
    expect(msg).toMatchObject({ title: 'Approve delete on orders?', body: 'agent via MariaDB → Shop\nDELETE FROM orders WHERE id = 1', approvalId: pending.id });
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
    await expect(run).rejects.toMatchObject({ errno: 1227 });
    await c.end();
    await proxy.admin('DELETE', `/push/subscriptions?endpoint=${encodeURIComponent(sub.json.endpoint)}`);
    await mdb.drop();
  });
});
