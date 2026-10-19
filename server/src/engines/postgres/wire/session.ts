import { randomUUID } from 'node:crypto';
import type net from 'node:net';
import type { Gate, GateOutcome } from '../../../gate.js';
import type { Approval, DatabaseConfig, ProxyUser } from '../../../store.js';
import type { Analysis, StatementAnalysis } from '../../types.js';
import { analyze } from '../analyze.js';
import type { PostgresExecutor } from '../executor.js';
import { errorResponse, flush, FrameReader, noticeResponse, parse as parseMessage, parseFields, query as queryMessage, Reader, type Frame } from './protocol.js';

const NOTICE_INTERVAL_MS = 30_000;
/** Stop reading from the client while this much is queued behind a held statement. */
const MAX_QUEUED_BYTES = 64 * 1024 * 1024;
const MAX_PARAM_CHARS = 2000;

interface Prepared {
  sql: string;
  analysis: Analysis;
}

interface Portal {
  statement: string;
  params: (string | null)[];
  /** Once one Execute of a portal is allowed, re-Executes (row-limited fetches) of it are too. */
  allowed: boolean;
}

/** Tracks completion of a forwarded statement so its audit row gets the row count / error. */
interface Finisher {
  kind: 'query' | 'execute';
  outcome: Pick<Extract<GateOutcome, { allowed: true }>, 'finish'>;
  rows: number;
  /** Which batch (ended by a Query or Sync → one ReadyForQuery) it belongs to. */
  batch: number;
}

const untracked = { finish: () => {} };

export interface SessionDeps {
  gate: Gate;
  executor: PostgresExecutor;
}

/**
 * One client connection relayed to one upstream connection. Client messages are processed
 * strictly in order; a statement that needs approval is held (everything after it queues) while
 * upstream output keeps flowing. Denials are turned into a *real* upstream error (a reference to
 * a non-existent marker relation) so the server's transaction state always matches what the
 * client is told: inside BEGIN the transaction becomes aborted; earlier statements in the same
 * implicit transaction roll back; the extended protocol skips to Sync on both sides.
 */
export class WireSession {
  private clientReader = new FrameReader();
  private upstreamReader = new FrameReader();
  private queue: Frame[] = [];
  private queuedBytes = 0;
  private processing = false;
  private closed = false;

  private prepared = new Map<string, Prepared>();
  private portals = new Map<string, Portal>();
  private finishers: Finisher[] = [];
  /** Marker relation name → error to show the client instead of upstream's "relation does not exist". */
  private injected = new Map<string, { code: string; message: string; detail?: string; hint?: string; batch: number }>();
  /** Batches sent upstream (each Query/Sync) and completed (each ReadyForQuery received). */
  private batchesSent = 0;
  private batchesDone = 0;
  private dropUntilSync = false;

  private txStatus: 'I' | 'T' | 'E' = 'I';
  private txSince: number | null = null;
  private hold: AbortController | null = null;

  constructor(
    private client: net.Socket,
    private upstream: net.Socket,
    private db: DatabaseConfig,
    private user: ProxyUser,
    private applicationName: string | null,
    private deps: SessionDeps,
    leftovers: { client: Buffer; upstream: Buffer },
    private onClose: () => void,
  ) {
    client.on('data', (d) => this.onClientData(d));
    upstream.on('data', (d) => this.onUpstreamData(d));
    client.on('close', () => this.close());
    upstream.on('close', () => this.close());
    client.on('error', () => this.close());
    upstream.on('error', () => this.close());
    if (leftovers.upstream.length) this.onUpstreamData(leftovers.upstream);
    if (leftovers.client.length) this.onClientData(leftovers.client);
  }

  /** A CancelRequest arrived for this session. Returns true if it cancelled a held statement. */
  cancelHold(): boolean {
    if (!this.hold) return false;
    this.hold.abort();
    return true;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.hold?.abort();
    for (const f of this.finishers) f.outcome.finish({ error: 'connection closed before completion' });
    this.finishers = [];
    this.client.destroy();
    this.upstream.destroy();
    this.onClose();
  }

  // ── client → upstream ──────────────────────────────────

  private onClientData(d: Buffer) {
    this.clientReader.push(d);
    try {
      for (let f = this.clientReader.next(); f; f = this.clientReader.next()) {
        this.queue.push(f);
        this.queuedBytes += f.raw.length;
      }
    } catch (err) {
      return this.fatal('08P01', `protocol violation: ${(err as Error).message}`);
    }
    if (this.queuedBytes > MAX_QUEUED_BYTES) this.client.pause();
    void this.process();
  }

  private async process() {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.queue.length && !this.closed) {
        const f = this.queue.shift()!;
        this.queuedBytes -= f.raw.length;
        if (this.client.isPaused() && this.queuedBytes < MAX_QUEUED_BYTES / 2) this.client.resume();
        await this.handleClient(f);
      }
    } catch (err) {
      this.fatal('XX000', `twophase internal error: ${(err as Error).message}`);
    } finally {
      this.processing = false;
    }
  }

  private send(buf: Buffer) {
    if (!this.closed) this.upstream.write(buf);
  }

  /** Query and Sync each end a batch: the server answers each with exactly one ReadyForQuery. */
  private sendBatchEnd(buf: Buffer) {
    this.send(buf);
    this.batchesSent++;
  }

  private track(kind: Finisher['kind'], outcome: Finisher['outcome']) {
    this.finishers.push({ kind, outcome, rows: 0, batch: this.batchesSent });
  }

  private async handleClient(f: Frame) {
    if (this.dropUntilSync) {
      // After a failure in an extended-protocol batch, the server discards until Sync; so do we.
      if (f.type === 'S') {
        this.dropUntilSync = false;
        this.sendBatchEnd(f.raw);
      } else if (f.type === 'X') this.terminate(f);
      return;
    }

    switch (f.type) {
      case 'Q': {
        const sql = new Reader(f.body).cstring();
        const analysis = await this.analyze(sql);
        const outcome = await this.check(sql, null, analysis, false);
        if (!outcome.allowed) return this.inject(outcome, 'simple');
        this.track('query', outcome);
        this.trackSessionEffects(analysis);
        return this.sendBatchEnd(f.raw);
      }
      case 'P': {
        const r = new Reader(f.body);
        const name = r.cstring();
        const sql = r.cstring();
        const analysis = await this.analyze(sql);
        // Deny early (the statement is never prepared upstream); "ask" waits for Execute.
        if (this.deps.gate.preview(this.db, this.user, analysis) === 'deny') {
          const outcome = await this.check(sql, null, analysis, true);
          if (!outcome.allowed) return this.inject(outcome, 'extended');
        }
        this.prepared.set(name, { sql, analysis });
        return this.send(f.raw);
      }
      case 'B': {
        const r = new Reader(f.body);
        const portal = r.cstring();
        const statement = r.cstring();
        this.portals.set(portal, { statement, params: readBindParams(r), allowed: false });
        return this.send(f.raw);
      }
      case 'E': {
        const portalName = new Reader(f.body).cstring();
        const portal = this.portals.get(portalName);
        const stmt = portal && this.prepared.get(portal.statement);
        if (!portal || !stmt) {
          // Not prepared through us: let the server report the missing portal/statement.
          this.track('execute', untracked);
          return this.send(f.raw);
        }
        if (portal.allowed) {
          this.track('execute', untracked); // a row-limited re-fetch of an already-allowed portal
          return this.send(f.raw);
        }
        const outcome = await this.check(stmt.sql, portal.params, stmt.analysis, true);
        if (!outcome.allowed) return this.inject(outcome, 'extended');
        portal.allowed = true;
        this.track('execute', outcome);
        this.trackSessionEffects(stmt.analysis);
        return this.send(f.raw);
      }
      case 'C': {
        const r = new Reader(f.body);
        const kind = String.fromCharCode(r.byte());
        const name = r.cstring();
        if (kind === 'S') this.prepared.delete(name);
        else this.portals.delete(name);
        return this.send(f.raw);
      }
      case 'S': // Sync
        return this.sendBatchEnd(f.raw);
      case 'D': // Describe
      case 'H': // Flush
      case 'd': // CopyData
      case 'c': // CopyDone
      case 'f': // CopyFail
        return this.send(f.raw);
      case 'F': {
        // Legacy fast-path function call: opaque to the classifier, so refuse it. It's answered like a simple query.
        return this.inject({ allowed: false, decision: 'denied', approvalId: null, sqlstate: '0A000', message: 'twophase: fast-path function calls are not supported' }, 'simple');
      }
      case 'X':
        return this.terminate(f);
      default:
        return this.fatal('08P01', `unexpected message type "${f.type}"`);
    }
  }

  private async analyze(sql: string): Promise<Analysis> {
    const catalog = await this.deps.executor.functionCatalog();
    const prepared = new Map<string, StatementAnalysis>();
    for (const [name, p] of this.prepared) if (p.analysis.statements.length === 1) prepared.set(name, p.analysis.statements[0]);
    for (const [name, a] of this.sqlPrepared) prepared.set(name, a);
    return analyze(sql, { catalog, prepared });
  }

  /** SQL-level PREPARE / DEALLOCATE (distinct from protocol-level Parse). */
  private sqlPrepared = new Map<string, StatementAnalysis>();
  private trackSessionEffects(analysis: Analysis) {
    for (const s of analysis.statements) {
      if (s.prepared) this.sqlPrepared.set(s.prepared.name, s.prepared.analysis);
      if (s.command === 'DEALLOCATE' || s.flags.includes('session_reset')) {
        const m = /DEALLOCATE\s+(?:PREPARE\s+)?("?)([^";\s]+)\1/i.exec(s.text);
        if (m && m[2].toUpperCase() !== 'ALL') this.sqlPrepared.delete(m[2]);
        else this.sqlPrepared.clear();
      }
    }
  }

  private async check(sql: string, params: (string | null)[] | null, analysis: Analysis, extended: boolean): Promise<GateOutcome> {
    const preview = this.deps.gate.preview(this.db, this.user, analysis);
    // About to wait for a human: let the client see results of everything before this first.
    if (preview === 'ask' && extended) this.send(flush());
    const hold = (this.hold = new AbortController());
    let noticeTimer: NodeJS.Timeout | null = null;
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
          applicationName: this.applicationName,
          transactionStatus: this.txStatus === 'I' ? 'idle' : this.txStatus === 'T' ? 'transaction' : 'failed',
          transactionAgeMs: this.txSince ? Date.now() - this.txSince : null,
        },
        estimate: () => this.deps.executor.estimate(analysis.statements, params ?? undefined),
        onWaiting: (approval: Approval) => {
          const started = Date.now();
          const notify = () =>
            this.client.write(
              noticeResponse({
                code: '00000',
                message: `twophase: waiting for approval (${Math.round((Date.now() - started) / 1000)}s)…`,
                detail: `Approval ${approval.id} for ${approval.operations.join(', ')}${approval.tables.length ? ` on ${approval.tables.join(', ')}` : ''}.`,
                hint: 'Approve or deny it in the Twophase app. Cancel (Ctrl+C) withdraws the request.',
              }),
            );
          notify();
          noticeTimer = setInterval(notify, NOTICE_INTERVAL_MS);
        },
      });
    } finally {
      if (noticeTimer) clearInterval(noticeTimer);
      this.hold = null;
    }
  }

  /**
   * Fails the current statement with a real upstream error (so transaction state stays in sync),
   * then shows the client our error instead of the marker's "relation does not exist".
   */
  private inject(outcome: Extract<GateOutcome, { allowed: false }>, mode: 'simple' | 'extended') {
    const marker = `twophase_denied_${randomUUID().replaceAll('-', '')}`;
    this.injected.set(marker, {
      batch: this.batchesSent,
      code: outcome.sqlstate,
      message: outcome.message,
      detail: outcome.approvalId ? `Approval ${outcome.approvalId} was ${outcome.decision}.` : undefined,
      hint: outcome.decision === 'denied' ? 'Ask the proxy operator if you need this permission.' : undefined,
    });
    const sql = `SELECT * FROM "${marker}"`;
    if (mode === 'simple') this.sendBatchEnd(queryMessage(sql));
    else {
      this.send(parseMessage('', sql));
      this.dropUntilSync = true;
    }
  }

  private terminate(f: Frame) {
    this.send(f.raw);
    this.upstream.end();
    this.client.end();
  }

  private fatal(code: string, message: string) {
    if (!this.closed) this.client.write(errorResponse({ severity: 'FATAL', code, message }));
    this.close();
  }

  // ── upstream → client ──────────────────────────────────

  private onUpstreamData(d: Buffer) {
    this.upstreamReader.push(d);
    try {
      for (let f = this.upstreamReader.next(); f; f = this.upstreamReader.next()) this.handleUpstream(f);
    } catch {
      this.fatal('08P01', 'protocol violation from upstream server');
    }
  }

  private handleUpstream(f: Frame) {
    switch (f.type) {
      case 'E': {
        const fields = parseFields(f.body);
        const msg = fields.get('M') ?? '';
        const marker = [...this.injected.keys()].find((m) => msg.includes(m));
        if (marker) {
          const { batch: _b, ...e } = this.injected.get(marker)!;
          this.injected.delete(marker);
          return this.client.write(errorResponse({ severity: 'ERROR', ...e }));
        }
        // Errors belong to the oldest unfinished statement of the batch the server is working on.
        if (this.finishers[0]?.batch === this.batchesDone) {
          this.finishers.shift()!.outcome.finish({ error: msg, sqlstate: fields.get('C') ?? null });
        }
        break;
      }
      case 'C': {
        const count = Number(/(\d+)$/.exec(f.body.subarray(0, -1).toString('utf8'))?.[1] ?? NaN);
        const head = this.finishers[0]?.batch === this.batchesDone ? this.finishers[0] : undefined;
        if (head?.kind === 'execute') {
          this.finishers.shift();
          head.outcome.finish({ rowCount: Number.isNaN(count) ? null : count });
        } else if (head && !Number.isNaN(count)) head.rows += count;
        break;
      }
      case 's': // PortalSuspended
      case 'I': {
        // EmptyQueryResponse
        const head = this.finishers[0]?.batch === this.batchesDone ? this.finishers[0] : undefined;
        if (head?.kind === 'execute') {
          this.finishers.shift();
          head.outcome.finish({ rowCount: null });
        }
        break;
      }
      case 'Z': {
        const status = String.fromCharCode(f.body[0]) as 'I' | 'T' | 'E';
        if (status === 'I') this.txSince = null;
        else if (this.txStatus === 'I') this.txSince = Date.now();
        this.txStatus = status;
        const ended = this.batchesDone++;
        while (this.finishers[0]?.batch === ended) {
          const head = this.finishers.shift()!;
          if (head.kind === 'query') head.outcome.finish({ rowCount: head.rows });
          else head.outcome.finish({ error: 'not executed: an earlier statement in the batch failed' });
        }
        for (const [marker, e] of this.injected) if (e.batch === ended) this.injected.delete(marker);
        break;
      }
    }
    if (!this.closed) this.client.write(f.raw);
  }
}

function readBindParams(r: Reader): (string | null)[] {
  const nFormats = r.int16();
  const formats: number[] = [];
  for (let i = 0; i < nFormats; i++) formats.push(r.int16());
  const n = r.int16();
  const params: (string | null)[] = [];
  for (let i = 0; i < n; i++) {
    const len = r.int32();
    if (len < 0) {
      params.push(null);
      continue;
    }
    const bytes = r.bytes(len);
    const binary = (nFormats === 1 ? formats[0] : formats[i]) === 1;
    const text = binary ? `<binary ${len} bytes>` : bytes.toString('utf8');
    params.push(text.length > MAX_PARAM_CHARS ? `${text.slice(0, MAX_PARAM_CHARS)}…` : text);
  }
  return params;
}
