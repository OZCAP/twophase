/**
 * MySQL client/server protocol framing: 3-byte length + 1-byte sequence id per packet; payloads
 * of 16 MB - 1 or more continue in the next packet. We relay packets byte-for-byte and parse only
 * what we need to gate and to follow the conversation.
 */

export const CAP = {
  LONG_PASSWORD: 1,
  FOUND_ROWS: 2,
  LONG_FLAG: 4,
  CONNECT_WITH_DB: 8,
  NO_SCHEMA: 16,
  COMPRESS: 32,
  ODBC: 64,
  LOCAL_FILES: 128,
  IGNORE_SPACE: 256,
  PROTOCOL_41: 512,
  INTERACTIVE: 1024,
  SSL: 2048,
  IGNORE_SIGPIPE: 4096,
  TRANSACTIONS: 8192,
  SECURE_CONNECTION: 32768,
  MULTI_STATEMENTS: 1 << 16,
  MULTI_RESULTS: 1 << 17,
  PS_MULTI_RESULTS: 1 << 18,
  PLUGIN_AUTH: 1 << 19,
  CONNECT_ATTRS: 1 << 20,
  PLUGIN_AUTH_LENENC: 1 << 21,
  CAN_HANDLE_EXPIRED_PASSWORDS: 1 << 22,
  SESSION_TRACK: 1 << 23,
  DEPRECATE_EOF: 1 << 24,
} as const;

export const STATUS = {
  IN_TRANS: 0x0001,
  AUTOCOMMIT: 0x0002,
  MORE_RESULTS: 0x0008,
  CURSOR_EXISTS: 0x0040,
} as const;

export const COM = {
  QUIT: 0x01,
  INIT_DB: 0x02,
  QUERY: 0x03,
  FIELD_LIST: 0x04,
  STATISTICS: 0x09,
  PROCESS_KILL: 0x0c,
  PING: 0x0e,
  CHANGE_USER: 0x11,
  STMT_PREPARE: 0x16,
  STMT_EXECUTE: 0x17,
  STMT_SEND_LONG_DATA: 0x18,
  STMT_CLOSE: 0x19,
  STMT_RESET: 0x1a,
  SET_OPTION: 0x1b,
  STMT_FETCH: 0x1c,
  RESET_CONNECTION: 0x1f,
} as const;

export const MAX_PAYLOAD = 0xffffff;

export interface Message {
  /** Sequence id of the first packet. */
  seq: number;
  /** Sequence id of the last packet (the reply continues from here + 1). */
  lastSeq: number;
  payload: Buffer;
  /** The packets exactly as received, for relaying. */
  raw: Buffer;
}

/** Splits a byte stream into logical messages (joining 16 MB continuation packets). */
export class PacketReader {
  private buf: Buffer = Buffer.alloc(0);
  private parts: { seq: number; payload: Buffer; raw: Buffer }[] = [];

  push(chunk: Buffer): Message[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: Message[] = [];
    for (;;) {
      if (this.buf.length < 4) break;
      const len = this.buf.readUIntLE(0, 3);
      if (this.buf.length < 4 + len) break;
      const raw = this.buf.subarray(0, 4 + len);
      this.parts.push({ seq: this.buf[3], payload: raw.subarray(4), raw });
      this.buf = this.buf.subarray(4 + len);
      if (len === MAX_PAYLOAD) continue;
      const parts = this.parts;
      this.parts = [];
      out.push({
        seq: parts[0].seq,
        lastSeq: parts[parts.length - 1].seq,
        payload: parts.length === 1 ? parts[0].payload : Buffer.concat(parts.map((p) => p.payload)),
        raw: parts.length === 1 ? parts[0].raw : Buffer.concat(parts.map((p) => p.raw)),
      });
    }
    return out;
  }

  /** Bytes received but not yet part of a complete message. */
  drain(): Buffer {
    const rest = Buffer.concat([...this.parts.map((p) => p.raw), this.buf]);
    this.parts = [];
    this.buf = Buffer.alloc(0);
    return rest;
  }
}

/** Frames a payload as packets starting at `seq` (splitting at 16 MB). */
export function packet(seq: number, payload: Buffer): Buffer {
  const out: Buffer[] = [];
  let offset = 0;
  for (;;) {
    const len = Math.min(MAX_PAYLOAD, payload.length - offset);
    const header = Buffer.alloc(4);
    header.writeUIntLE(len, 0, 3);
    header[3] = seq & 0xff;
    out.push(header, payload.subarray(offset, offset + len));
    offset += len;
    seq++;
    if (len < MAX_PAYLOAD) break;
  }
  return Buffer.concat(out);
}

export class Reader {
  pos = 0;
  constructor(readonly buf: Buffer) {}
  get done() {
    return this.pos >= this.buf.length;
  }
  u8() {
    return this.buf[this.pos++];
  }
  u16() {
    const v = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return v;
  }
  u24() {
    const v = this.buf.readUIntLE(this.pos, 3);
    this.pos += 3;
    return v;
  }
  u32() {
    const v = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  bytes(n: number) {
    const v = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  /** Length-encoded integer (null for the 0xFB NULL marker). */
  lenenc(): number | null {
    const first = this.u8();
    if (first < 0xfb) return first;
    if (first === 0xfb) return null;
    if (first === 0xfc) return this.u16();
    if (first === 0xfd) return this.u24();
    const v = this.buf.readBigUInt64LE(this.pos);
    this.pos += 8;
    return Number(v);
  }
  lenencBytes(): Buffer | null {
    const n = this.lenenc();
    return n === null ? null : this.bytes(n);
  }
  nul(): Buffer {
    const end = this.buf.indexOf(0, this.pos);
    const v = this.buf.subarray(this.pos, end < 0 ? this.buf.length : end);
    this.pos = end < 0 ? this.buf.length : end + 1;
    return v;
  }
  rest(): Buffer {
    const v = this.buf.subarray(this.pos);
    this.pos = this.buf.length;
    return v;
  }
}

export function lenencInt(n: number): Buffer {
  if (n < 0xfb) return Buffer.from([n]);
  if (n < 0x10000) return Buffer.from([0xfc, n & 0xff, n >> 8]);
  if (n < 0x1000000) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff, n >> 16]);
  const b = Buffer.alloc(9);
  b[0] = 0xfe;
  b.writeBigUInt64LE(BigInt(n), 1);
  return b;
}

export const lenencBytes = (b: Buffer) => Buffer.concat([lenencInt(b.length), b]);
export const nulString = (s: string | Buffer) => Buffer.concat([Buffer.isBuffer(s) ? s : Buffer.from(s, 'utf8'), Buffer.from([0])]);

export function okPacket(seq: number, opts: { affectedRows?: number; lastInsertId?: number; status?: number; warnings?: number; info?: string } = {}): Buffer {
  const status = Buffer.alloc(4);
  status.writeUInt16LE(opts.status ?? STATUS.AUTOCOMMIT, 0);
  status.writeUInt16LE(opts.warnings ?? 0, 2);
  return packet(
    seq,
    Buffer.concat([Buffer.from([0x00]), lenencInt(opts.affectedRows ?? 0), lenencInt(opts.lastInsertId ?? 0), status, Buffer.from(opts.info ?? '', 'utf8')]),
  );
}

export function errPacket(seq: number, code: number, sqlstate: string, message: string): Buffer {
  const head = Buffer.alloc(3);
  head[0] = 0xff;
  head.writeUInt16LE(code, 1);
  return packet(seq, Buffer.concat([head, Buffer.from(`#${sqlstate}`, 'ascii'), Buffer.from(message, 'utf8')]));
}

export interface ErrInfo {
  code: number;
  sqlstate: string;
  message: string;
}

export function parseErr(payload: Buffer): ErrInfo {
  const r = new Reader(payload);
  r.u8();
  const code = r.u16();
  let sqlstate = 'HY000';
  if (payload[r.pos] === 0x23) {
    r.u8();
    sqlstate = r.bytes(5).toString('ascii');
  }
  return { code, sqlstate, message: r.rest().toString('utf8') };
}

export interface OkInfo {
  affectedRows: number;
  lastInsertId: number;
  status: number;
}

/** OK packet (0x00 or, as an end-of-rows marker with DEPRECATE_EOF, 0xFE). */
export function parseOk(payload: Buffer): OkInfo {
  const r = new Reader(payload);
  r.u8();
  const affectedRows = r.lenenc() ?? 0;
  const lastInsertId = r.lenenc() ?? 0;
  const status = r.pos + 2 <= payload.length ? r.u16() : 0;
  return { affectedRows, lastInsertId, status };
}

/** Classic EOF packet: 0xFE, warnings, status. */
export function parseEofStatus(payload: Buffer): number {
  return payload.length >= 5 ? payload.readUInt16LE(3) : 0;
}

/** An EOF / end-of-rows marker rather than a row (rows starting 0xFE are ≥ 16 MB). */
export const isEof = (payload: Buffer) => payload[0] === 0xfe && payload.length < MAX_PAYLOAD;

/** Character sets whose multibyte sequences can contain a byte that looks like `\` or a quote. */
const UNSAFE_COLLATION_IDS = new Set([1, 84, 13, 88, 28, 87, 95, 96, 248, 249, 250]);
const LATIN1_COLLATION_IDS = new Set([5, 8, 15, 31, 47, 48, 49, 94]);

export const unsafeCharset = (collationId: number) => UNSAFE_COLLATION_IDS.has(collationId);
export const textEncoding = (collationId: number): BufferEncoding => (LATIN1_COLLATION_IDS.has(collationId) ? 'latin1' : 'utf8');
