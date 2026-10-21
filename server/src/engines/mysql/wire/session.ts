import type net from 'node:net';
import type { Gate, GateOutcome } from '../../../gate.js';
import type { DatabaseConfig, ProxyUser } from '../../../store.js';
import type { Analysis, StatementAnalysis } from '../../types.js';
import type { MysqlExecutor } from '../executor.js';
import { CAP, COM, errPacket, isEof, okPacket, packet, PacketReader, parseEofStatus, parseErr, parseOk, Reader, STATUS, textEncoding, type Message } from './protocol.js';

const MAX_QUEUED_BYTES = 64 * 1024 * 1024;
const MAX_PARAM_CHARS = 2000;

/** Commands that never go upstream through the proxy. */
const REFUSED: Record<number, string> = {
  0x05: 'COM_CREATE_DB',
  0x06: 'COM_DROP_DB',
  0x07: 'COM_REFRESH',
  0x08: 'COM_SHUTDOWN',
  0x0a: 'COM_PROCESS_INFO',
  0x0b: 'COM_CONNECT',
  0x0d: 'COM_DEBUG',
  0x0f: 'COM_TIME',
  0x10: 'COM_DELAYED_INSERT',
  0x12: 'COM_BINLOG_DUMP',
  0x13: 'COM_TABLE_DUMP',
  0x14: 'COM_CONNECT_OUT',
  0x15: 'COM_REGISTER_SLAVE',
  0x1d: 'COM_DAEMON',
  0x1e: 'COM_BINLOG_DUMP_GTID',
  0x20: 'COM_CLONE',
  0xfa: 'COM_STMT_BULK_EXECUTE',
};

/** Error codes and SQLSTATEs MySQL clients know. */
export const ER = {
  ACCESS_DENIED: { code: 1045, state: '28000' },
  DB_ACCESS_DENIED: { code: 1044, state: '42000' },
  NO_DB: { code: 1046, state: '3D000' },
  BAD_DB: { code: 1049, state: '42000' },
  SPECIFIC_ACCESS_DENIED: { code: 1227, state: '42000' },
  QUERY_INTERRUPTED: { code: 1317, state: '70100' },
  UNKNOWN_COM: { code: 1047, state: '08S01' },
  NO_SUCH_THREAD: { code: 1094, state: 'HY000' },
  KILL_DENIED: { code: 1095, state: 'HY000' },
  UNKNOWN_STMT_HANDLER: { code: 1243, state: 'HY000' },
  NOT_SUPPORTED: { code: 1235, state: '42000' },
} as const;

interface PreparedStmt {
  sql: string;
  analysis: Analysis;
  params: number;
  /** Parameter types from the last execute that sent them (types are only re-sent when they change). */
  types: number[] | null;
}

/** Follows one command's response packets to see where it ends and what it did. */
class ResponseTracker {
  private state: 'first' | 'columns' | 'columnsEof' | 'rows' | 'prepare' | 'list' | 'single' | 'done';
  private remaining = 0;
  rows = 0;
  affected: number | null = null;
  error: { code: number; sqlstate: string; message: string } | null = null;
  /** For COM_STMT_PREPARE: the statement id and parameter count from the reply. */
  prepared: { id: number; params: number } | null = null;
  private prepareParts: number[] = [];

  constructor(
    readonly kind: 'results' | 'prepare' | 'list' | 'single',
    private deprecateEof: boolean,
    private onStatus: (status: number) => void,
  ) {
    this.state = kind === 'results' ? 'first' : kind;
  }

  get done() {
    return this.state === 'done';
  }

  feed(p: Buffer) {
    if (p[0] === 0xff && this.state !== 'columns') {
      this.error = parseErr(p);
      this.state = 'done';
      return;
    }
    switch (this.state) {
      case 'single':
        if (p[0] === 0x00 || isEof(p)) this.status(p);
        this.state = 'done';
        return;
      case 'list':
        // COM_FIELD_LIST: column definitions until EOF.
        if (isEof(p)) {
          this.status(p);
          this.state = 'done';
        }
        return;
      case 'prepare': {
        if (!this.prepared) {
          const r = new Reader(p);
          r.u8();
          const id = r.u32();
          const columns = r.u16();
          const params = r.u16();
          this.prepared = { id, params };
          const eof = this.deprecateEof ? 0 : 1;
          this.prepareParts = [params ? params + eof : 0, columns ? columns + eof : 0].filter((n) => n > 0);
        } else if (this.prepareParts.length) {
          if (--this.prepareParts[0] === 0) this.prepareParts.shift();
        }
        if (this.prepareParts.length === 0) this.state = 'done';
        return;
      }
      case 'first':
        if (p[0] === 0x00) {
          const ok = parseOk(p);
          this.affected = (this.affected ?? 0) + ok.affectedRows;
          this.onStatus(ok.status);
          if (!(ok.status & STATUS.MORE_RESULTS)) this.state = 'done';
          return;
        }
        if (p[0] === 0xfb) {
          // LOCAL INFILE request: never negotiated, so never valid.
          this.error = { code: 2027, sqlstate: 'HY000', message: 'unexpected LOCAL INFILE request' };
          this.state = 'done';
          return;
        }
        this.remaining = new Reader(p).lenenc() ?? 0;
        this.state = this.remaining > 0 ? 'columns' : this.deprecateEof ? 'rows' : 'columnsEof';
        return;
      case 'columns':
        if (--this.remaining === 0) this.state = this.deprecateEof ? 'rows' : 'columnsEof';
        return;
      case 'columnsEof': {
        const status = parseEofStatus(p);
        this.onStatus(status);
        // A server-side cursor was opened: rows come later via COM_STMT_FETCH.
        this.state = status & STATUS.CURSOR_EXISTS ? 'done' : 'rows';
        return;
      }
      case 'rows':
        if (isEof(p)) {
          const status = this.status(p);
          if (status & STATUS.CURSOR_EXISTS) this.state = 'done';
          else this.state = status & STATUS.MORE_RESULTS ? 'first' : 'done';
          return;
        }
        this.rows++;
        return;
    }
  }

  private status(p: Buffer): number {
    const status = p[0] === 0xfe && p.length < 9 ? parseEofStatus(p) : parseOk(p).status;
    this.onStatus(status);
    return status;
  }
}

export interface MysqlSessionDeps {
  gate: Gate;
  executor: MysqlExecutor;
  /** Find another live session (for KILL), by the connection id we gave it or its upstream thread id. */
  findSession(id: number): MysqlWireSession | undefined;
  /** Kill a statement running upstream, from a fresh connection with the same login. */
  killUpstream(session: MysqlWireSession): Promise<void>;
}

export interface MysqlSessionInit {
  connectionId: number;
  upstreamThreadId: number;
  caps: number;
  charset: number;
  sqlMode: string;
  status: number;
  applicationName: string | null;
  login: { user: string; password: string };
}

/**
 * One MySQL client connection relayed to one upstream connection. The protocol is strictly
 * request/response, so commands are handled one at a time: a statement that needs approval is
 * held (later commands queue) and the client keeps being read, so a disconnect withdraws the
 * request. A denied statement is answered locally with an ERR packet: unlike Postgres, a failed
 * statement does not abort a MySQL transaction, so the session state stays the same on both sides.
 */
export class MysqlWireSession {
  private clientReader = new PacketReader();
  private upstreamReader = new PacketReader();
  private queue: Message[] = [];
  private queuedBytes = 0;
  private processing = false;
  private closed = false;
  private tracker: ResponseTracker | null = null;
  private trackerDone: (() => void) | null = null;
  private hold: AbortController | null = null;
  private running = false;
  private internal: ((payload: Buffer) => void) | null = null;
  private internalDone: (() => void) | null = null;

  private prepared = new Map<number, PreparedStmt>();
  private sqlPrepared = new Map<string, StatementAnalysis>();
  private ansiQuotes: boolean;
  private noBackslashEscapes: boolean;
  private status: number;
  private txSince: number | null = null;

  constructor(
    private client: net.Socket,
    private upstream: net.Socket,
    readonly db: DatabaseConfig,
    readonly user: ProxyUser,
    readonly init: MysqlSessionInit,
    private deps: MysqlSessionDeps,
    leftovers: { client: Buffer; upstream: Buffer },
    private onClose: () => void,
  ) {
    const modes = init.sqlMode.toUpperCase().split(',');
    this.ansiQuotes = modes.includes('ANSI_QUOTES');
    this.noBackslashEscapes = modes.includes('NO_BACKSLASH_ESCAPES');
    this.status = init.status;
    client.on('data', (d) => this.onClientData(d));
    upstream.on('data', (d) => this.onUpstreamData(d));
    client.on('close', () => this.close());
    upstream.on('close', () => this.close());
    client.on('error', () => this.close());
    upstream.on('error', () => this.close());
    client.resume();
    upstream.resume();
    if (leftovers.upstream.length) this.onUpstreamData(leftovers.upstream);
    if (leftovers.client.length) this.onClientData(leftovers.client);
  }

  private get deprecateEof() {
    return !!(this.init.caps & CAP.DEPRECATE_EOF);
  }

  /** KILL QUERY from another connection of the same client. */
  async cancel(): Promise<void> {
    if (this.hold) {
      this.hold.abort();
      return;
    }
    if (this.running) await this.deps.killUpstream(this);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.hold?.abort();
    this.trackerDone?.();
    this.internalDone?.();
    this.client.destroy();
    this.upstream.destroy();
    this.onClose();
  }

  // ── client → upstream ──────────────────────────────────

  private onClientData(d: Buffer) {
    for (const m of this.clientReader.push(d)) {
      this.queue.push(m);
      this.queuedBytes += m.raw.length;
    }
    if (this.queuedBytes > MAX_QUEUED_BYTES) this.client.pause();
    void this.process();
  }

  private async process() {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.queue.length && !this.closed) {
        const m = this.queue.shift()!;
        this.queuedBytes -= m.raw.length;
        if (this.client.isPaused() && this.queuedBytes < MAX_QUEUED_BYTES / 2) this.client.resume();
        await this.handle(m);
      }
    } catch (err) {
      this.client.write(errPacket(1, 1105, 'HY000', `twophase internal error: ${(err as Error).message}`));
      this.close();
    } finally {
      this.processing = false;
    }
  }

  private reply(m: Message, err: { code: number; state: string }, message: string) {
    this.client.write(errPacket(m.lastSeq + 1, err.code, err.state, message));
  }

  private async handle(m: Message) {
    const cmd = m.payload[0];
    switch (cmd) {
      case COM.QUIT:
        this.upstream.write(m.raw);
        return this.close();
      case COM.QUERY:
        return this.query(m);
      case COM.INIT_DB: {
        const name = m.payload.subarray(1).toString('utf8');
        if (!this.isCurrentDatabase(name)) return this.reply(m, ER.DB_ACCESS_DENIED, `twophase: this connection can only use database '${this.db.slug}'`);
        return this.forward(packet(m.seq, Buffer.concat([Buffer.from([COM.INIT_DB]), Buffer.from(this.db.database, 'utf8')])), 'single');
      }
      case COM.FIELD_LIST: {
        const table = new Reader(m.payload.subarray(1)).nul().toString('utf8').toLowerCase();
        const outcome = await this.check(`-- field list (${table})`, null, {
          statements: [{ text: `SHOW COLUMNS FROM ${table}`, command: 'FIELD LIST', kind: 'read', accesses: [{ op: 'read', verb: 'select', table }], flags: [] }],
          error: null,
        });
        if (!outcome.allowed) return this.deny(m, outcome);
        return this.forwardTracked(m.raw, 'list', outcome);
      }
      case COM.PING:
      case COM.STATISTICS:
      case COM.STMT_RESET:
      case COM.SET_OPTION:
        return this.forward(m.raw, 'single');
      case COM.RESET_CONNECTION:
        this.prepared.clear();
        this.sqlPrepared.clear();
        await this.forward(m.raw, 'single');
        return this.refreshSqlMode();
      case COM.PROCESS_KILL:
        return this.kill(m, m.payload.length >= 5 ? m.payload.readUInt32LE(1) : 0, false);
      case COM.CHANGE_USER:
        this.reply(m, ER.NOT_SUPPORTED, 'twophase: COM_CHANGE_USER is not supported; open a new connection instead');
        return this.close();
      case COM.STMT_PREPARE:
        return this.prepare(m);
      case COM.STMT_EXECUTE:
        return this.execute(m);
      case COM.STMT_SEND_LONG_DATA:
        // No reply; the data belongs to the next execute, which is what gets gated.
        this.upstream.write(m.raw);
        return;
      case COM.STMT_CLOSE:
        this.prepared.delete(m.payload.readUInt32LE(1));
        this.upstream.write(m.raw);
        return;
      case COM.STMT_FETCH: {
        // Rows of a cursor opened by an execute that was already allowed.
        return this.forward(m.raw, 'results');
      }
      default:
        if (REFUSED[cmd]) return this.reply(m, ER.SPECIFIC_ACCESS_DENIED, `twophase: ${REFUSED[cmd]} is not allowed through the proxy`);
        return this.reply(m, ER.UNKNOWN_COM, 'Unknown command');
    }
  }

  private isCurrentDatabase(name: string) {
    const n = name.toLowerCase();
    return n === this.db.slug.toLowerCase() || n === this.db.database.toLowerCase();
  }

  private async analyze(sql: string): Promise<Analysis> {
    return this.deps.executor.analyze(sql, {
      database: this.db.database,
      databaseAliases: [this.db.slug],
      prepared: this.sqlPrepared,
      ansiQuotes: this.ansiQuotes,
      noBackslashEscapes: this.noBackslashEscapes,
    });
  }

  private async query(m: Message) {
    let raw = m.raw;
    const sql = m.payload.subarray(1).toString(textEncoding(this.init.charset));
    const analysis = await this.analyze(sql);
    if (analysis.statements.length === 0) return this.forward(raw, 'results');

    const only = analysis.statements.length === 1 ? analysis.statements[0] : null;
    if (only && (only.flags.includes('kill_query') || only.flags.includes('kill_connection'))) {
      const id = Number(/(\d+)\s*;?\s*$/.exec(only.text)?.[1] ?? 0);
      return this.kill(m, id, only.flags.includes('kill_query'));
    }
    // `USE <slug>` when the slug isn't the real database name: send the real name.
    if (only?.flags.includes('use_database') && this.db.slug !== this.db.database) {
      raw = packet(m.seq, Buffer.concat([Buffer.from([COM.QUERY]), Buffer.from(`USE \`${this.db.database.replaceAll('`', '``')}\``, 'utf8')]));
    }

    const outcome = await this.check(sql, null, analysis);
    if (!outcome.allowed) return this.deny(m, outcome);
    this.trackSessionEffects(analysis);
    const t = await this.forwardTracked(raw, 'results', outcome);
    // New or dropped stored functions change how later statements classify.
    if (analysis.statements.some((s) => s.kind === 'admin' && /sql_mode/i.test(s.text))) await this.refreshSqlMode();
  }

  private trackSessionEffects(analysis: Analysis) {
    for (const s of analysis.statements) {
      if (s.prepared) this.sqlPrepared.set(s.prepared.name, s.prepared.analysis);
      if (s.command === 'DEALLOCATE PREPARE') {
        const m = /PREPARE\s+(`?)([^`;\s]+)\1/i.exec(s.text);
        if (m) this.sqlPrepared.delete(m[2].toLowerCase());
      }
    }
  }

  private async prepare(m: Message) {
    const sql = m.payload.subarray(1).toString(textEncoding(this.init.charset));
    const analysis = await this.analyze(sql);
    // Refuse at prepare time only what policy would deny outright; asking happens at execute.
    if (this.deps.gate.preview(this.db, this.user, analysis) === 'deny') {
      const outcome = await this.check(sql, null, analysis);
      if (!outcome.allowed) return this.deny(m, outcome);
      outcome.finish({});
    }
    const tracker = await this.forward(m.raw, 'prepare');
    if (tracker.prepared && !tracker.error) this.prepared.set(tracker.prepared.id, { sql, analysis, params: tracker.prepared.params, types: null });
  }

  private async execute(m: Message) {
    const id = m.payload.readUInt32LE(1);
    const stmt = this.prepared.get(id);
    if (!stmt) return this.reply(m, ER.UNKNOWN_STMT_HANDLER, `Unknown prepared statement handler (${id}) given to mysqld_stmt_execute`);
    const params = decodeParams(m.payload, stmt);
    const outcome = await this.check(stmt.sql, params, await this.analyze(stmt.sql));
    if (!outcome.allowed) return this.deny(m, outcome);
    return this.forwardTracked(m.raw, 'results', outcome);
  }

  private async kill(m: Message, id: number, queryOnly: boolean) {
    const target = this.deps.findSession(id);
    if (!target) return this.reply(m, ER.NO_SUCH_THREAD, `Unknown thread id: ${id}`);
    if (target.user.id !== this.user.id) return this.reply(m, ER.KILL_DENIED, `You are not owner of thread ${id}`);
    if (!queryOnly && target === this) return this.close();
    if (queryOnly) await target.cancel().catch(() => {});
    else target.close();
    this.client.write(okPacket(m.lastSeq + 1, { status: this.status }));
  }

  private deny(m: Message, outcome: Extract<GateOutcome, { allowed: false }>) {
    const err = outcome.sqlstate === '57014' ? ER.QUERY_INTERRUPTED : ER.SPECIFIC_ACCESS_DENIED;
    const detail = outcome.approvalId ? ` (approval ${outcome.approvalId} was ${outcome.decision})` : '';
    this.reply(m, err, `${outcome.message}${detail}`);
  }

  private async check(sql: string, params: (string | null)[] | null, analysis: Analysis): Promise<GateOutcome> {
    const hold = (this.hold = new AbortController());
    try {
      return await this.deps.gate.check({
        surface: 'wire',
        db: this.db,
        user: this.user,
        sql,
        params,
        analysis,
        signal: hold.signal,
        session: {
          applicationName: this.init.applicationName,
          transactionStatus: this.status & STATUS.IN_TRANS ? 'transaction' : 'idle',
          transactionAgeMs: this.txSince ? Date.now() - this.txSince : null,
        },
        estimate: () => this.deps.executor.estimate(analysis.statements, params ?? undefined),
      });
    } finally {
      this.hold = null;
    }
  }

  // ── upstream → client ──────────────────────────────────

  /** Sends a command upstream and waits until its whole reply has been relayed. */
  private forward(raw: Buffer, kind: ResponseTracker['kind']): Promise<ResponseTracker> {
    const tracker = new ResponseTracker(kind, this.deprecateEof, (s) => this.setStatus(s));
    this.tracker = tracker;
    this.running = true;
    return new Promise((resolve) => {
      this.trackerDone = () => {
        this.tracker = null;
        this.trackerDone = null;
        this.running = false;
        resolve(tracker);
      };
      this.upstream.write(raw);
    });
  }

  private async forwardTracked(raw: Buffer, kind: ResponseTracker['kind'], outcome: Extract<GateOutcome, { allowed: true }>) {
    const t = await this.forward(raw, kind);
    if (t.error) outcome.finish({ error: t.error.message, sqlstate: t.error.sqlstate });
    else outcome.finish({ rowCount: t.affected ?? t.rows });
    return t;
  }

  private onUpstreamData(d: Buffer) {
    for (const m of this.upstreamReader.push(d)) {
      // Replies to the proxy's own queries are not for the client.
      if (this.internal) {
        this.internal(m.payload);
        continue;
      }
      this.client.write(m.raw);
      const t = this.tracker;
      if (!t) continue;
      t.feed(m.payload);
      if (t.done) this.trackerDone?.();
    }
  }

  private setStatus(status: number) {
    const inTrans = !!(status & STATUS.IN_TRANS);
    if (inTrans && !(this.status & STATUS.IN_TRANS)) this.txSince = Date.now();
    if (!inTrans) this.txSince = null;
    this.status = status;
  }

  /** After something may have changed sql_mode, re-read it so we keep lexing SQL the way the server does. */
  private async refreshSqlMode() {
    let phase: 'first' | 'columns' | 'columnsEof' | 'rows' = 'first';
    let columns = 0;
    let mode: string | null = null;
    await new Promise<void>((resolve) => {
      const done = () => {
        this.internal = null;
        this.internalDone = null;
        resolve();
      };
      this.internalDone = done;
      this.internal = (p) => {
        if (p[0] === 0xff || (phase === 'first' && p[0] === 0x00)) return done();
        if (phase === 'first') {
          columns = new Reader(p).lenenc() ?? 0;
          phase = 'columns';
        } else if (phase === 'columns') {
          if (--columns === 0) phase = this.deprecateEof ? 'rows' : 'columnsEof';
        } else if (phase === 'columnsEof') phase = 'rows';
        else if (isEof(p)) {
          this.setStatus(p.length < 9 ? parseEofStatus(p) : parseOk(p).status);
          done();
        } else mode ??= new Reader(p).lenencBytes()?.toString('utf8') ?? '';
      };
      this.upstream.write(packet(0, Buffer.concat([Buffer.from([COM.QUERY]), Buffer.from('SELECT @@SESSION.sql_mode', 'utf8')])));
    });
    if (mode !== null) {
      const modes = (mode as string).toUpperCase().split(',');
      this.ansiQuotes = modes.includes('ANSI_QUOTES');
      this.noBackslashEscapes = modes.includes('NO_BACKSLASH_ESCAPES');
    }
  }
}

/** Best-effort decoding of COM_STMT_EXECUTE parameters, for showing to the approver. */
function decodeParams(payload: Buffer, stmt: PreparedStmt): (string | null)[] | null {
  if (stmt.params === 0) return null;
  try {
    const r = new Reader(payload);
    r.bytes(1 + 4 + 1 + 4);
    const nullBitmap = r.bytes((stmt.params + 7) >> 3);
    const newTypes = r.u8();
    if (newTypes) {
      stmt.types = [];
      for (let i = 0; i < stmt.params; i++) stmt.types.push(r.u16());
    }
    const types = stmt.types;
    if (!types) return null;
    const out: (string | null)[] = [];
    for (let i = 0; i < stmt.params; i++) {
      if (nullBitmap[i >> 3] & (1 << (i & 7))) {
        out.push(null);
        continue;
      }
      const type = types[i] & 0xff;
      const unsigned = !!(types[i] & 0x8000);
      let v: string;
      switch (type) {
        case 1:
          v = String(unsigned ? r.u8() : (r.u8() << 24) >> 24);
          break;
        case 2:
        case 13:
          v = String(unsigned ? r.u16() : (r.u16() << 16) >> 16);
          break;
        case 3:
        case 9: {
          const n = r.u32();
          v = String(unsigned ? n : n | 0);
          break;
        }
        case 8: {
          const b = r.bytes(8);
          v = (unsigned ? b.readBigUInt64LE() : b.readBigInt64LE()).toString();
          break;
        }
        case 4:
          v = String(r.bytes(4).readFloatLE());
          break;
        case 5:
          v = String(r.bytes(8).readDoubleLE());
          break;
        case 6:
          v = 'NULL';
          break;
        case 7:
        case 10:
        case 12:
        case 11: {
          const len = r.u8();
          r.bytes(len);
          v = '<date/time>';
          break;
        }
        default: {
          const b = r.lenencBytes();
          v = b ? (b.length > MAX_PARAM_CHARS ? `${b.subarray(0, MAX_PARAM_CHARS).toString('utf8')}…` : b.toString('utf8')) : '';
        }
      }
      out.push(v);
    }
    return out;
  } catch {
    return null;
  }
}
