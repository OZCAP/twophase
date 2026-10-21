import { randomBytes, randomInt } from 'node:crypto';
import net from 'node:net';
import type { Gate } from '../../../gate.js';
import { canOnlyRead } from '../../../policy.js';
import type { EventBus } from '../../../events.js';
import type { Store } from '../../../store.js';
import type { ExecutorRegistry } from '../../index.js';
import { NATIVE, nonce as makeNonce, SHA2, verifyScramble } from './auth.js';
import { CAP, errPacket, nulString, okPacket, packet, PacketReader, Reader, STATUS, unsafeCharset, type Message } from './protocol.js';
import { ER, MysqlWireSession } from './session.js';
import { connectMysqlUpstream, UpstreamError } from './upstream.js';

export interface MysqlWireDeps {
  store: Store;
  gate: Gate;
  executors: ExecutorRegistry;
  events: EventBus;
}

const HANDSHAKE_TIMEOUT_MS = 30_000;
const SERVER_VERSION = '8.0.40-twophase';
const UTF8MB4_GENERAL_CI = 45;

/** What we offer clients. No TLS (tailnet only; the token is never sent), compression or LOCAL INFILE. */
export const ADVERTISED_CAPS =
  CAP.LONG_PASSWORD |
  CAP.FOUND_ROWS |
  CAP.LONG_FLAG |
  CAP.CONNECT_WITH_DB |
  CAP.IGNORE_SPACE |
  CAP.PROTOCOL_41 |
  CAP.INTERACTIVE |
  CAP.IGNORE_SIGPIPE |
  CAP.TRANSACTIONS |
  CAP.SECURE_CONNECTION |
  CAP.MULTI_STATEMENTS |
  CAP.MULTI_RESULTS |
  CAP.PS_MULTI_RESULTS |
  CAP.PLUGIN_AUTH |
  CAP.CONNECT_ATTRS |
  CAP.PLUGIN_AUTH_LENENC |
  CAP.SESSION_TRACK |
  CAP.DEPRECATE_EOF;

class HandshakeError extends Error {
  constructor(
    readonly err: { code: number; state: string },
    message: string,
  ) {
    super(message);
  }
}

interface HandshakeResponse {
  caps: number;
  charset: number;
  username: string;
  auth: Buffer;
  database: string | null;
  plugin: string;
  attrs: Record<string, string>;
}

function parseHandshakeResponse(payload: Buffer): HandshakeResponse {
  const r = new Reader(payload);
  const caps = r.u32() >>> 0;
  r.u32();
  const charset = r.u8();
  r.bytes(23);
  const username = r.nul().toString('utf8');
  let auth: Buffer;
  if (caps & CAP.PLUGIN_AUTH_LENENC) auth = r.lenencBytes() ?? Buffer.alloc(0);
  else if (caps & CAP.SECURE_CONNECTION) auth = r.bytes(r.u8());
  else auth = r.nul();
  const database = caps & CAP.CONNECT_WITH_DB && !r.done ? r.nul().toString('utf8') || null : null;
  const plugin = caps & CAP.PLUGIN_AUTH && !r.done ? r.nul().toString('ascii') : '';
  const attrs: Record<string, string> = {};
  if (caps & CAP.CONNECT_ATTRS && !r.done) {
    const end = r.pos + (r.lenenc() ?? 0);
    while (r.pos < end) {
      const k = r.lenencBytes()?.toString('utf8') ?? '';
      attrs[k] = r.lenencBytes()?.toString('utf8') ?? '';
    }
  }
  return { caps, charset, username, auth, database, plugin, attrs };
}

function greeting(connectionId: number, challenge: Buffer, plugin: string): Buffer {
  const caps = ADVERTISED_CAPS >>> 0;
  const head = Buffer.alloc(4);
  head.writeUInt32LE(connectionId, 0);
  const mid = Buffer.alloc(1 + 2 + 1 + 2 + 2 + 1 + 10);
  let o = 0;
  mid[o++] = 0; // filler
  mid.writeUInt16LE(caps & 0xffff, o);
  o += 2;
  mid[o++] = UTF8MB4_GENERAL_CI;
  mid.writeUInt16LE(STATUS.AUTOCOMMIT, o);
  o += 2;
  mid.writeUInt16LE(caps >>> 16, o);
  o += 2;
  mid[o++] = challenge.length + 1;
  return packet(
    0,
    Buffer.concat([Buffer.from([10]), nulString(SERVER_VERSION), head, challenge.subarray(0, 8), mid, challenge.subarray(8), Buffer.from([0]), nulString(plugin)]),
  );
}

/** MySQL wire-protocol endpoint for MySQL and MariaDB databases: `mysql -h proxy -P 3307 -u <client> -p <db-slug>`. */
export function startMysqlWireListener(deps: MysqlWireDeps, opts: { host: string; port: number }) {
  const sessions = new Map<number, MysqlWireSession>();
  const byUpstreamThread = new Map<number, MysqlWireSession>();
  const unsubscribe = deps.events.on('access.changed', ({ userId, databaseId }) => {
    for (const session of sessions.values()) {
      if (session.user.id === userId || session.db.id === databaseId) {
        void session.cancel().catch(() => {});
        session.close();
      }
    }
  });
  const server = net.createServer((socket) => void handle(socket));

  async function killUpstream(target: MysqlWireSession) {
    const conn = await connectMysqlUpstream(target.db, {
      login: target.init.login,
      caps: target.init.caps,
      charset: UTF8MB4_GENERAL_CI,
      attrs: { program_name: 'twophase (cancel)' },
    });
    try {
      await conn.query(`KILL QUERY ${target.init.upstreamThreadId}`);
    } finally {
      conn.socket.destroy();
    }
  }

  async function handle(socket: net.Socket) {
    socket.setNoDelay(true);
    socket.on('error', () => socket.destroy());
    const reader = new PacketReader();
    const pending: Message[] = [];
    let waiter: ((m: Message) => void) | null = null;
    const onData = (d: Buffer) => {
      for (const m of reader.push(d)) {
        if (waiter) {
          const w = waiter;
          waiter = null;
          w(m);
        } else pending.push(m);
      }
    };
    socket.on('data', onData);
    const next = () =>
      new Promise<Message>((resolve, reject) => {
        const m = pending.shift();
        if (m) return resolve(m);
        waiter = resolve;
        socket.once('close', () => reject(new Error('closed')));
      });
    const timer = setTimeout(() => socket.destroy(), HANDSHAKE_TIMEOUT_MS);

    let connectionId: number;
    do connectionId = randomInt(1, 2 ** 31 - 1);
    while (sessions.has(connectionId));
    const challenge = makeNonce();
    let seq = 1;
    const fail = (err: { code: number; state: string }, message: string) => {
      clearTimeout(timer);
      socket.end(errPacket(seq, err.code, err.state, message));
    };

    try {
      socket.write(greeting(connectionId, challenge, SHA2));
      const first = await next();
      seq = first.lastSeq + 1;
      if (first.payload.length === 32) {
        throw new HandshakeError(ER.NOT_SUPPORTED, 'twophase does not offer TLS on this port (traffic stays on your tailnet; the token is never sent). Connect with --ssl-mode=DISABLED.');
      }
      const resp = parseHandshakeResponse(first.payload);
      for (const [cap, name] of [
        [CAP.PROTOCOL_41, 'PROTOCOL_41'],
        [CAP.PLUGIN_AUTH, 'PLUGIN_AUTH'],
      ] as const) {
        if (!(resp.caps & cap)) throw new HandshakeError(ER.NOT_SUPPORTED, `twophase needs a client with ${name} support (MySQL 5.7+ / MariaDB 10.2+ client libraries)`);
      }
      if (unsafeCharset(resp.charset)) throw new HandshakeError(ER.NOT_SUPPORTED, 'twophase does not support this character set; use utf8mb4');

      // ── authenticate the client ──
      const user = deps.store.getMysqlLogin(resp.username);
      const unknown = randomBytes(20).toString('hex');
      let plugin = resp.plugin;
      let reply = resp.auth;
      if ((plugin !== NATIVE && plugin !== SHA2) || reply.length === 0) {
        // Another plugin (sha256_password, ed25519, …): ask for caching_sha2_password with the same challenge.
        // A client whose plugin differs from the greeting's may send nothing and expect a switch to its own.
        plugin = plugin === NATIVE ? NATIVE : SHA2;
        socket.write(packet(seq, Buffer.concat([Buffer.from([0xfe]), nulString(plugin), challenge, Buffer.from([0])])));
        const switched = await next();
        seq = switched.lastSeq + 1;
        reply = switched.payload;
      }
      const stored = plugin === NATIVE ? user?.mysql.mysqlNativeHash : user?.mysql.mysqlSha2Hash;
      const ok = verifyScramble(plugin, user ? stored : plugin === NATIVE ? unknown.slice(0, 40) : unknown + unknown.slice(0, 24), challenge, reply);
      const denied = `Access denied for user '${resp.username}' (using password: ${reply.length ? 'YES' : 'NO'})`;
      if (!ok || !user) {
        if (user && !user.mysqlLogin) throw new HandshakeError(ER.ACCESS_DENIED, `${denied}: this client's token was issued before MySQL support — rotate it in Twophase`);
        throw new HandshakeError(ER.ACCESS_DENIED, denied);
      }
      if (plugin === SHA2) socket.write(packet(seq++, Buffer.from([0x01, 0x03]))); // fast auth success
      if (!user.enabled) throw new HandshakeError(ER.ACCESS_DENIED, `${denied}: client is disabled`);

      if (!resp.database) throw new HandshakeError(ER.NO_DB, 'No database selected: connect with the database name, e.g. mysql -D <slug>');
      const db = deps.store.getDatabaseBySlug(resp.database);
      if (!db || !db.enabled || db.engine === 'postgres') {
        const hint = db?.engine === 'postgres' ? ': it is a Postgres database, connect with psql on the Postgres port' : '';
        throw new HandshakeError(ER.BAD_DB, `Unknown database '${resp.database}'${hint}`);
      }
      if (!user.access.some((a) => a.databaseId === db.id && a.allowWire)) {
        throw new HandshakeError(ER.DB_ACCESS_DENIED, `Access denied for user '${resp.username}' to database '${resp.database}'`);
      }

      // ── upstream ──
      const readOnly = canOnlyRead(deps.store.listRules({ databaseId: db.id }), db, user.id);
      const login = readOnly && db.readonlyUser ? { user: db.readonlyUser, password: db.readonlyPassword ?? '' } : { user: db.user, password: db.password };
      const caps = (resp.caps & ADVERTISED_CAPS) >>> 0;
      const program = resp.attrs.program_name || 'client';
      let upstream;
      let sqlMode = '';
      try {
        upstream = await connectMysqlUpstream(db, {
          login,
          caps,
          charset: resp.charset,
          attrs: { program_name: `${program} (via twophase:${user.username})`.slice(0, 80), _client_name: 'twophase' },
        });
        if (/mariadb/i.test(upstream.greeting.serverVersion) && resp.charset > 250) {
          // MySQL 8 clients default to utf8mb4_0900_ai_ci, which MariaDB may not know: same charset, MariaDB's default collation.
          await upstream.query('SET NAMES utf8mb4');
        }
        [[sqlMode = ''] = []] = await upstream.query('SELECT @@SESSION.sql_mode');
        if (readOnly) await upstream.query('SET SESSION TRANSACTION READ ONLY');
      } catch (err) {
        upstream?.socket.destroy();
        const e = err instanceof UpstreamError ? err : new UpstreamError((err as Error).message);
        throw new HandshakeError({ code: e.code, state: e.sqlstate }, `twophase could not connect to the database: ${e.message}`);
      }

      clearTimeout(timer);
      socket.off('data', onData);
      socket.pause();
      socket.write(okPacket(seq, { status: upstream.status }));
      deps.store.touchUser(user.id);
      const { mysql: _verifier, ...proxyUser } = user;
      const session = new MysqlWireSession(
        socket,
        upstream.socket,
        db,
        proxyUser,
        {
          connectionId,
          upstreamThreadId: upstream.greeting.connectionId,
          caps,
          charset: resp.charset,
          sqlMode,
          status: upstream.status,
          applicationName: resp.attrs.program_name ?? null,
          login,
        },
        {
          gate: deps.gate,
          executor: deps.executors.mysql(db),
          findSession: (id) => sessions.get(id) ?? byUpstreamThread.get(id),
          killUpstream,
        },
        { client: Buffer.concat([...pending.map((m) => m.raw), reader.drain()]), upstream: upstream.leftover },
        () => {
          sessions.delete(connectionId);
          byUpstreamThread.delete(upstream.greeting.connectionId);
        },
      );
      sessions.set(connectionId, session);
      byUpstreamThread.set(upstream.greeting.connectionId, session);
    } catch (err) {
      if (err instanceof HandshakeError) return fail(err.err, err.message);
      clearTimeout(timer);
      socket.destroy();
    }
  }

  return {
    server,
    listen(): Promise<number> {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(opts.port, opts.host, () => resolve((server.address() as net.AddressInfo).port));
      });
    },
    async close() {
      unsubscribe();
      for (const s of sessions.values()) s.close();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
