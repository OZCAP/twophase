import { randomInt } from 'node:crypto';
import net from 'node:net';
import type { Gate } from '../../../gate.js';
import { canOnlyRead } from '../../../policy.js';
import type { EventBus } from '../../../events.js';
import { timeoutMillis } from '../../safety.js';
import type { Store } from '../../../store.js';
import { ENGINE_LABELS, type ExecutorRegistry } from '../../index.js';
import {
  authOk,
  authSasl,
  authSaslContinue,
  authSaslFinal,
  backendKeyData,
  CANCEL_REQUEST,
  errorResponse,
  FrameReader,
  GSSENC_REQUEST,
  negotiateProtocolVersion,
  readyForQuery,
  Reader,
  SSL_REQUEST,
  type Frame,
} from './protocol.js';
import { dummyVerifier, ScramServerSession } from './scram.js';
import { WireSession } from './session.js';
import { connectUpstream, sendUpstreamCancel, UpstreamError } from './upstream.js';

export interface WireDeps {
  store: Store;
  gate: Gate;
  executors: ExecutorRegistry;
  events: EventBus;
  approvalTimeoutSeconds: number;
}

const STARTUP_TIMEOUT_MS = 30_000;

/** Startup parameters passed through to the real server. Anything else is dropped or rejected. */
const PASSTHROUGH_PARAMS = new Set(['client_encoding', 'datestyle', 'timezone', 'extra_float_digits', 'search_path', 'intervalstyle', 'lc_monetary', 'lc_numeric', 'lc_time']);
/** Settings allowed in the `options` startup parameter (-c name=value). */
const OPTION_SETTINGS = new Set([...PASSTHROUGH_PARAMS, 'statement_timeout', 'lock_timeout', 'application_name']);

class StartupError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Parses `-c a=b --c=d` style options into settings, rejecting anything not allowlisted. */
function parseOptions(options: string): Record<string, string> {
  const out: Record<string, string> = {};
  const tokens = options.match(/(?:\\.|\S)+/g) ?? [];
  for (let i = 0; i < tokens.length; i++) {
    let t = tokens[i].replace(/\\(.)/g, '$1');
    if (t === '-c') t = (tokens[++i] ?? '').replace(/\\(.)/g, '$1');
    else if (t.startsWith('-c')) t = t.slice(2);
    else if (t.startsWith('--')) t = t.slice(2);
    else throw new StartupError('42501', `startup option "${t}" is not allowed through twophase`);
    const eq = t.indexOf('=');
    const name = (eq < 0 ? t : t.slice(0, eq)).toLowerCase().replace(/-/g, '_');
    if (!OPTION_SETTINGS.has(name)) throw new StartupError('42501', `setting "${name}" can't be set at connection time through twophase`);
    out[name] = eq < 0 ? '' : t.slice(eq + 1);
  }
  return out;
}

function validateParams(params: Record<string, string>) {
  if ('replication' in params) throw new StartupError('42501', 'replication connections are not supported through twophase');
  const enc = params.client_encoding?.toLowerCase().replace(/[-_]/g, '');
  if (enc && enc !== 'utf8' && enc !== 'unicode') throw new StartupError('22023', 'twophase requires client_encoding UTF8');
  // The proxy parses SQL as standard_conforming_strings=on; a different lexing on the server could desync them.
  for (const [k, v] of Object.entries(params)) {
    if (k.toLowerCase() === 'standard_conforming_strings' && !/^(on|true|1)$/i.test(v)) {
      throw new StartupError('42501', 'standard_conforming_strings must stay on through twophase');
    }
  }
}

/** Postgres wire-protocol endpoint: `postgresql://<client>:<token>@proxy:6432/<db-slug>`. */
export function startWireListener(deps: WireDeps, opts: { host: string; port: number }) {
  const sessions = new Map<string, { session: WireSession; db: { host: string; port: number; sslmode: any }; upstreamKey: { pid: number; secret: number } }>();
  const unsubscribe = deps.events.on('access.changed', ({ userId, databaseId }) => {
    for (const entry of sessions.values()) {
      if (entry.session.user.id === userId || entry.session.db.id === databaseId) {
        void sendUpstreamCancel(entry.db, entry.upstreamKey).catch(() => {});
        entry.session.close();
      }
    }
  });

  const server = net.createServer((socket) => {
    socket.setNoDelay(true);
    void handle(socket).catch(() => socket.destroy());
  });

  async function handle(socket: net.Socket) {
    const reader = new FrameReader();
    const waiting: (() => void)[] = [];
    let ended = false;
    const onData = (d: Buffer) => {
      reader.push(d);
      waiting.splice(0).forEach((w) => w());
    };
    socket.on('data', onData);
    socket.on('close', () => {
      ended = true;
      waiting.splice(0).forEach((w) => w());
    });
    socket.on('error', () => {});
    const timer = setTimeout(() => socket.destroy(), STARTUP_TIMEOUT_MS);

    const wait = () => new Promise<void>((r) => waiting.push(r));
    const nextStartup = async () => {
      for (;;) {
        const p = reader.nextStartup();
        if (p) return p;
        if (ended) throw new Error('closed');
        await wait();
      }
    };
    const nextFrame = async (): Promise<Frame> => {
      for (;;) {
        const f = reader.next();
        if (f) return f;
        if (ended) throw new Error('closed');
        await wait();
      }
    };
    const fatal = (code: string, message: string) => {
      socket.end(errorResponse({ severity: 'FATAL', code, message }));
    };

    try {
      // ── startup negotiation ──
      let params: Record<string, string> | null = null;
      while (!params) {
        const packet = await nextStartup();
        const r = new Reader(packet);
        const code = r.int32();
        if (code === SSL_REQUEST || code === GSSENC_REQUEST) {
          // Client-side TLS is not offered (run behind WireGuard/Tailscale or a TLS-terminating proxy).
          socket.write('N');
          continue;
        }
        if (code === CANCEL_REQUEST) {
          const key = `${r.int32()}:${r.int32()}`;
          const target = sessions.get(key);
          if (target && !target.session.cancelHold()) await sendUpstreamCancel(target.db, target.upstreamKey);
          socket.destroy();
          return;
        }
        if (code >> 16 !== 3) return fatal('0A000', `unsupported frontend protocol ${code >> 16}.${code & 0xffff}`);
        const p: Record<string, string> = {};
        for (let k = r.cstring(); k; k = r.cstring()) p[k] = r.cstring();
        const unknownProtocolOptions = Object.keys(p).filter((k) => k.startsWith('_pq_.'));
        if ((code & 0xffff) > 0 || unknownProtocolOptions.length) socket.write(negotiateProtocolVersion(0, unknownProtocolOptions));
        for (const k of unknownProtocolOptions) delete p[k];
        params = p;
      }

      const username = params.user;
      if (!username) return fatal('28000', 'no user specified');
      const dbSlug = params.database || username;
      validateParams(params);
      const options = params.options ? parseOptions(params.options) : {};

      // ── SCRAM-SHA-256 authentication against the client's token ──
      const user = deps.store.getUserByUsername(username);
      const scram = new ScramServerSession(user?.scram ?? dummyVerifier());
      const authFailed = () => fatal('28P01', `password authentication failed for user "${username}"`);
      socket.write(authSasl(['SCRAM-SHA-256']));
      const initial = await nextFrame();
      if (initial.type !== 'p') return fatal('08P01', 'expected SASL initial response');
      const ir = new Reader(initial.body);
      if (ir.cstring() !== 'SCRAM-SHA-256') return fatal('28000', 'only SCRAM-SHA-256 authentication is supported');
      const len = ir.int32();
      let serverFirst: string;
      try {
        serverFirst = scram.first(ir.bytes(len).toString('utf8'));
      } catch (err) {
        return fatal('08P01', (err as Error).message);
      }
      socket.write(authSaslContinue(serverFirst));
      const response = await nextFrame();
      if (response.type !== 'p') return fatal('08P01', 'expected SASL response');
      const serverFinal = scram.final(response.body.toString('utf8'));
      if (!serverFinal || !user) return authFailed();
      socket.write(authSaslFinal(serverFinal));
      if (!user.enabled) return fatal('28000', `client "${username}" is disabled`);

      const db = deps.store.getDatabaseBySlug(dbSlug);
      if (!db || !db.enabled) return fatal('3D000', `database "${dbSlug}" does not exist`);
      if (db.engine !== 'postgres') return fatal('3D000', `database "${dbSlug}" is ${ENGINE_LABELS[db.engine]}: connect with a MySQL client on the MySQL port`);
      if (!user.access.some((a) => a.databaseId === db.id && a.allowWire)) {
        return fatal('28000', `client "${username}" has no Postgres access to database "${dbSlug}"`);
      }
      socket.write(authOk());

      // ── upstream ──
      const readOnly = canOnlyRead(deps.store.listRules({ databaseId: db.id }), db, user.id);
      const login = readOnly && db.readonlyUser ? { user: db.readonlyUser, password: db.readonlyPassword ?? '' } : { user: db.user, password: db.password };
      const appName = options.application_name ?? params.application_name ?? null;
      const passthrough: Record<string, string> = {};
      for (const [k, v] of Object.entries({ ...params, ...options })) if (PASSTHROUGH_PARAMS.has(k.toLowerCase())) passthrough[k] = v;
      const serverOptions = [
        // A statement held for approval inside a transaction keeps its locks; don't let the session linger past that.
        `-c idle_in_transaction_session_timeout=${(deps.approvalTimeoutSeconds + 60) * 1000}`,
        `-c statement_timeout=${Math.min(db.statementTimeoutMs, timeoutMillis(options.statement_timeout ?? '') ?? db.statementTimeoutMs)}`,
        ...(options.lock_timeout ? [`-c lock_timeout=${options.lock_timeout}`] : []),
        ...(readOnly ? ['-c default_transaction_read_only=on'] : []),
      ].join(' ');

      let upstream;
      try {
        upstream = await connectUpstream(db, login, {
          ...passthrough,
          application_name: `${appName || 'client'} (via twophase:${user.username})`.slice(0, 63),
          options: serverOptions,
        });
      } catch (err) {
        const e = err instanceof UpstreamError ? err : new UpstreamError((err as Error).message);
        return fatal(e.sqlstate, `twophase could not connect to the database: ${e.message}`);
      }

      for (const ps of upstream.parameterStatus) socket.write(ps);
      let key: string;
      let pid: number;
      let secret: number;
      do {
        pid = randomInt(1, 2 ** 31 - 1);
        secret = randomInt(-(2 ** 31), 2 ** 31 - 1);
        key = `${pid}:${secret}`;
      } while (sessions.has(key));
      socket.write(backendKeyData(pid, secret));
      socket.write(readyForQuery('I'));

      clearTimeout(timer);
      socket.off('data', onData);
      deps.store.touchUser(user.id);
      const session = new WireSession(
        socket,
        upstream.socket,
        db,
        user,
        appName,
        { gate: deps.gate, executor: deps.executors.postgres(db) },
        { client: reader.drain(), upstream: upstream.leftover },
        () => sessions.delete(key),
      );
      sessions.set(key, { session, db, upstreamKey: upstream.backendKey });
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof StartupError) return fatal(err.code, err.message);
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
      for (const { session } of sessions.values()) session.close();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
