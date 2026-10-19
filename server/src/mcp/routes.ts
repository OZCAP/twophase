import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { Router, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import { bearerToken, hashToken, mysqlVerifier } from '../auth.js';
import { createDatabaseMcpServer, type McpDeps } from './tools.js';

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  databaseId: string;
  userId: string;
  lastSeen: number;
}

const SESSION_IDLE_MS = 60 * 60 * 1000;

function rpcError(res: Response, status: number, message: string) {
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null });
}

/** Hosted MCP endpoint per database: `POST|GET|DELETE /mcp/:dbSlug` with `Authorization: Bearer tp_…`. */
export function mcpRouter(deps: McpDeps) {
  const { store } = deps;
  const sessions = new Map<string, Session>();
  const router = Router();

  const sweep = setInterval(() => {
    const cutoff = Date.now() - SESSION_IDLE_MS;
    for (const s of sessions.values()) if (s.lastSeen < cutoff) void s.transport.close();
  }, 60_000);
  sweep.unref();

  router.all('/mcp/:slug', async (req, res) => {
    const token = bearerToken(req);
    const user = token ? store.getUserByTokenHash(hashToken(token)) : null;
    if (!user || !user.enabled) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return rpcError(res, 401, 'Invalid or missing proxy token');
    }
    // Clients from before MySQL support: derive their MySQL verifiers the first time the token is seen.
    if (!user.mysqlLogin) store.setMysqlVerifier(user.id, mysqlVerifier(token!));
    const db = store.getDatabaseBySlug(req.params.slug);
    if (!db || !db.enabled) return rpcError(res, 404, 'Unknown database');
    if (!user.access.some((a) => a.databaseId === db.id && a.allowMcp)) return rpcError(res, 403, 'This token has no MCP access to this database');

    const sessionId = req.header('mcp-session-id');
    if (sessionId) {
      const session = sessions.get(sessionId);
      if (!session || session.userId !== user.id || session.databaseId !== db.id) return rpcError(res, 404, 'Session not found');
      session.lastSeen = Date.now();
      return session.transport.handleRequest(req, res, req.body);
    }

    if (req.method !== 'POST' || !isInitializeRequest(req.body)) return rpcError(res, 400, 'Bad Request: no valid session ID provided');

    const mcpServer = createDatabaseMcpServer(db.id, user.id, deps);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server: mcpServer, databaseId: db.id, userId: user.id, lastSeen: Date.now() });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };
    store.touchUser(user.id);
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  return {
    router,
    async close() {
      clearInterval(sweep);
      await Promise.all([...sessions.values()].map((s) => s.transport.close()));
    },
  };
}
