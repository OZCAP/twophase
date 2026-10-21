import express from 'express';
import { existsSync } from 'node:fs';
import type { Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { adminRouter, type AdminAuth } from './admin.js';
import { ApprovalService } from './approvals.js';
import { forgetAdminToken, resolveAdminTokenHash } from './auth.js';
import type { Config } from './config.js';
import { initAnalyzer } from './engines/postgres/analyze.js';
import { ExecutorRegistry } from './engines/index.js';
import { startMysqlWireListener } from './engines/mysql/wire/listener.js';
import { startWireListener } from './engines/postgres/wire/listener.js';
import { EventBus } from './events.js';
import { Gate } from './gate.js';
import { mcpRouter } from './mcp/routes.js';
import { PushService } from './push/index.js';
import { Housekeeping } from './housekeeping.js';
import { Store } from './store.js';
import { localApiWhois, type Whois } from './tailscaleAuth.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

/** `overrides.whois` lets tests stand in for tailscaled. */
export function createApp(config: Config, overrides: { whois?: Whois } = {}) {
  if (config.adminAuth === 'tailscale') {
    // X-Forwarded-For is only trustworthy if nobody but `tailscale serve` (on loopback) can reach us.
    if (!LOOPBACK_HOSTS.has(config.host)) throw new Error('ADMIN_AUTH=tailscale requires HOST=127.0.0.1 (expose it with `tailscale serve`)');
  }

  const store = new Store(config.dataDir);
  const housekeeping = new Housekeeping(store, config);
  const events = new EventBus();
  const push = new PushService(store, config);
  const approvals = new ApprovalService(store, events, push, config.approvalTimeoutSeconds);
  const gate = new Gate(store, approvals, events);
  const executors = new ExecutorRegistry();
  let adminAuth: AdminAuth;
  if (config.adminAuth === 'tailscale') {
    forgetAdminToken(store);
    adminAuth = { mode: 'tailscale', whois: overrides.whois ?? localApiWhois(config.tailscaleSocket) };
  } else {
    adminAuth = { mode: 'token', tokenHash: resolveAdminTokenHash(store, { adminToken: config.adminToken, reset: config.resetAdminToken }) };
  }

  const mcp = mcpRouter({ store, gate, executors, config });
  const wire = config.wire.enabled
    ? startWireListener({ store, gate, executors, events, approvalTimeoutSeconds: config.approvalTimeoutSeconds }, { host: config.wire.host, port: config.wire.port })
    : null;

  const mysqlWire = config.mysqlWire.enabled
    ? startMysqlWireListener({ store, gate, executors, events }, { host: config.mysqlWire.host, port: config.mysqlWire.port })
    : null;

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '4mb' }));
  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });
  app.use('/admin/api', adminRouter({ store, approvals, executors, events, push, config, adminAuth }));
  app.use(mcp.router);
  if (existsSync(config.webDir)) app.use(express.static(config.webDir));

  let http: HttpServer | null = null;
  return {
    app,
    store,
    approvals,
    /** Loads the SQL parser, then starts HTTP (admin + MCP) and the Postgres and MySQL listeners. */
    async listen(): Promise<{ http: HttpServer; httpPort: number; wirePort: number | null; mysqlWirePort: number | null }> {
      await initAnalyzer();
      http = await new Promise<HttpServer>((resolve) => {
        const s = app.listen(config.port, config.host, () => resolve(s));
      });
      housekeeping.start();
      const wirePort = wire ? await wire.listen() : null;
      const mysqlWirePort = mysqlWire ? await mysqlWire.listen() : null;
      return { http, httpPort: (http.address() as AddressInfo).port, wirePort, mysqlWirePort };
    },
    async close() {
      housekeeping.stop();
      approvals.shutdown();
      http?.close();
      await wire?.close();
      await mysqlWire?.close();
      await mcp.close();
      await executors.closeAll();
      store.close();
    },
  };
}
