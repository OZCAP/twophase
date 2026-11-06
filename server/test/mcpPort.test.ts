import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { createTestDatabase, postgresAvailable, startProxy, textOf, type TestDatabase, type TestProxy } from './helpers.js';

describe('MCP_PORT config', () => {
  it('serves MCP on the main port by default', () => {
    expect(loadConfig({}).mcp).toBeNull();
  });

  it('takes a separate MCP port, with an optional public port', () => {
    expect(loadConfig({ MCP_PORT: '8788' }).mcp).toEqual({ port: 8788, publicPort: 8788 });
    expect(loadConfig({ MCP_PORT: '8788', MCP_PUBLIC_PORT: '8443' }).mcp).toEqual({ port: 8788, publicPort: 8443 });
    // Compose passes unset variables as empty strings.
    expect(loadConfig({ MCP_PORT: '', MCP_PUBLIC_PORT: '' }).mcp).toBeNull();
  });

  it('rejects bad or clashing ports', () => {
    expect(() => loadConfig({ MCP_PORT: 'abc' })).toThrow(/MCP_PORT must be a port number/);
    expect(() => loadConfig({ MCP_PORT: '70000' })).toThrow(/MCP_PORT must be a port number/);
    expect(() => loadConfig({ MCP_PORT: '8788', MCP_PUBLIC_PORT: '0' })).toThrow(/MCP_PUBLIC_PORT must be a port number/);
    expect(() => loadConfig({ MCP_PUBLIC_PORT: '8443' })).toThrow(/needs MCP_PORT/);
    expect(() => loadConfig({ MCP_PORT: '8787' })).toThrow(/must differ from PORT/);
    expect(() => loadConfig({ PORT: '9000', MCP_PORT: '9000' })).toThrow(/must differ from PORT/);
  });
});

describe('MCP on its own port', () => {
  let proxy: TestProxy;

  beforeAll(async () => {
    proxy = await startProxy({ mcp: { port: 0, publicPort: 8443 } });
  });

  afterAll(async () => {
    await proxy?.close();
  });

  it('listens separately from the UI', () => {
    expect(proxy.mcpBase).not.toBe(proxy.base);
  });

  it('answers MCP on the MCP port only', async () => {
    const onMcp = await fetch(`${proxy.mcpBase}/mcp/shop`, { method: 'POST' });
    expect(onMcp.status).toBe(401);
    expect(await onMcp.json()).toMatchObject({ error: { message: 'Invalid or missing proxy token' } });

    const onUi = await fetch(`${proxy.base}/mcp/shop`, { method: 'POST' });
    expect(onUi.status).toBe(404);
  });

  it('keeps the admin API off the MCP port', async () => {
    expect((await fetch(`${proxy.mcpBase}/admin/api/status`)).status).toBe(404);
    expect((await fetch(`${proxy.mcpBase}/healthz`)).status).toBe(200);
  });

  it('tells the UI which port MCP clients should use', async () => {
    expect((await proxy.admin('GET', '/status')).mcp).toEqual({ port: 8443 });
  });
});

describe('MCP on the main port', () => {
  it('reports no separate MCP port to the UI', async () => {
    const proxy = await startProxy();
    try {
      expect(proxy.mcpBase).toBe(proxy.base);
      expect((await proxy.admin('GET', '/status')).mcp).toEqual({ port: null });
    } finally {
      await proxy.close();
    }
  });
});

const available = await postgresAvailable();

describe.skipIf(!available)('hosted MCP on its own port against real Postgres', () => {
  let tdb: TestDatabase;
  let proxy: TestProxy;

  beforeAll(async () => {
    tdb = await createTestDatabase();
    proxy = await startProxy({ mcp: { port: 0, publicPort: 0 } });
  });

  afterAll(async () => {
    await proxy?.close();
    await tdb?.drop();
  });

  it('runs tools over the MCP port', async () => {
    const { client } = await proxy.seed(tdb);
    const agent = await proxy.mcp(client.token, 'shop');
    try {
      const r = await agent.callTool({ name: 'query', arguments: { sql: 'SELECT count(*) AS n FROM orders' } });
      expect(r.isError).toBeFalsy();
      expect(textOf(r)).toContain('"n"');
    } finally {
      await agent.close();
    }
  });
});
