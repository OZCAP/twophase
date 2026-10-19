/**
 * Minimal Postgres v3 wire-protocol framing and message builders.
 * Typed messages: 1-byte type + int32 length (including itself) + body.
 * Startup-phase packets have no type byte: int32 length + int32 code + payload.
 */

export const PROTOCOL_3_0 = 196608;
export const SSL_REQUEST = 80877103;
export const GSSENC_REQUEST = 80877104;
export const CANCEL_REQUEST = 80877102;

/** Upper bound on any single message we will buffer (the server's own limit is ~1 GB; ours is far stricter). */
export const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;

export interface Frame {
  type: string;
  body: Buffer;
  /** The complete message, header included, for forwarding byte-for-byte. */
  raw: Buffer;
}

export class ProtocolError extends Error {}

/** Splits a byte stream into messages. */
export class FrameReader {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
  }

  get buffered() {
    return this.buf.length;
  }

  /** Remaining bytes not yet consumed (handed over when switching readers). */
  drain(): Buffer {
    const rest = this.buf;
    this.buf = Buffer.alloc(0);
    return rest;
  }

  next(): Frame | null {
    if (this.buf.length < 5) return null;
    const len = this.buf.readInt32BE(1);
    if (len < 4 || len > MAX_MESSAGE_BYTES) throw new ProtocolError(`invalid message length ${len}`);
    if (this.buf.length < len + 1) return null;
    const raw = this.buf.subarray(0, len + 1);
    this.buf = this.buf.subarray(len + 1);
    return { type: String.fromCharCode(raw[0]), body: raw.subarray(5), raw };
  }

  /** Startup-phase packet (no type byte). Returns the payload after the length. */
  nextStartup(): Buffer | null {
    if (this.buf.length < 4) return null;
    const len = this.buf.readInt32BE(0);
    if (len < 8 || len > 10_000) throw new ProtocolError(`invalid startup packet length ${len}`);
    if (this.buf.length < len) return null;
    const payload = this.buf.subarray(4, len);
    this.buf = this.buf.subarray(len);
    return payload;
  }
}

export class Reader {
  private off = 0;
  constructor(private b: Buffer) {}
  byte() {
    return this.b[this.off++];
  }
  int16() {
    const v = this.b.readInt16BE(this.off);
    this.off += 2;
    return v;
  }
  int32() {
    const v = this.b.readInt32BE(this.off);
    this.off += 4;
    return v;
  }
  cstring() {
    const end = this.b.indexOf(0, this.off);
    if (end < 0) throw new ProtocolError('unterminated string');
    const s = this.b.toString('utf8', this.off, end);
    this.off = end + 1;
    return s;
  }
  bytes(n: number) {
    const v = this.b.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }
  get remaining() {
    return this.b.length - this.off;
  }
}

const cstr = (s: string) => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])]);
const int32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n);
  return b;
};
const int16 = (n: number) => {
  const b = Buffer.alloc(2);
  b.writeInt16BE(n);
  return b;
};

export function message(type: string, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from(type, 'ascii'), int32(body.length + 4), body]);
}

function untyped(...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([int32(body.length + 4), body]);
}

// ── backend → client ───────────────────────────────────────

export interface ErrorFields {
  severity: 'ERROR' | 'FATAL' | 'NOTICE' | 'WARNING';
  code: string;
  message: string;
  detail?: string;
  hint?: string;
}

function fields(f: ErrorFields): Buffer {
  const parts = [Buffer.from('S'), cstr(f.severity), Buffer.from('V'), cstr(f.severity), Buffer.from('C'), cstr(f.code), Buffer.from('M'), cstr(f.message)];
  if (f.detail) parts.push(Buffer.from('D'), cstr(f.detail));
  if (f.hint) parts.push(Buffer.from('H'), cstr(f.hint));
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

export const errorResponse = (f: ErrorFields) => message('E', fields(f));
export const noticeResponse = (f: Omit<ErrorFields, 'severity'> & { severity?: 'NOTICE' | 'WARNING' }) =>
  message('N', fields({ severity: 'NOTICE', ...f }));
export const readyForQuery = (status: 'I' | 'T' | 'E') => message('Z', Buffer.from(status, 'ascii'));
export const authOk = () => message('R', int32(0));
export const authSasl = (mechanisms: string[]) => message('R', int32(10), ...mechanisms.map(cstr), Buffer.from([0]));
export const authSaslContinue = (data: string) => message('R', int32(11), Buffer.from(data, 'utf8'));
export const authSaslFinal = (data: string) => message('R', int32(12), Buffer.from(data, 'utf8'));
export const parameterStatus = (name: string, value: string) => message('S', cstr(name), cstr(value));
export const backendKeyData = (pid: number, secret: number) => message('K', int32(pid), int32(secret));
export const negotiateProtocolVersion = (minor: number, unrecognized: string[]) =>
  message('v', int32(minor), int32(unrecognized.length), ...unrecognized.map(cstr));

/** Parses ErrorResponse / NoticeResponse fields into { code letter → value }. */
export function parseFields(body: Buffer): Map<string, string> {
  const out = new Map<string, string>();
  const r = new Reader(body);
  while (r.remaining > 0) {
    const code = r.byte();
    if (code === 0) break;
    out.set(String.fromCharCode(code), r.cstring());
  }
  return out;
}

// ── client → backend ───────────────────────────────────────

export const sslRequest = () => untyped(int32(SSL_REQUEST));
export const cancelRequest = (pid: number, secret: number) => untyped(int32(CANCEL_REQUEST), int32(pid), int32(secret));
export const startupMessage = (params: Record<string, string>) =>
  untyped(int32(PROTOCOL_3_0), ...Object.entries(params).flatMap(([k, v]) => [cstr(k), cstr(v)]), Buffer.from([0]));
export const passwordMessage = (password: string) => message('p', cstr(password));
export const saslInitialResponse = (mechanism: string, data: string) => {
  const d = Buffer.from(data, 'utf8');
  return message('p', cstr(mechanism), int32(d.length), d);
};
export const saslResponse = (data: string) => message('p', Buffer.from(data, 'utf8'));
export const query = (sql: string) => message('Q', cstr(sql));
export const parse = (name: string, sql: string) => message('P', cstr(name), cstr(sql), int16(0));
export const flush = () => message('H');
export const terminate = () => message('X');
