import net from 'node:net';
import tls from 'node:tls';
import type { DatabaseConfig } from '../../../store.js';
import { NATIVE, rsaEncryptPassword, scramble, SHA2 } from './auth.js';
import { CAP, COM, isEof, lenencBytes, lenencInt, nulString, packet, PacketReader, parseErr, parseOk, Reader, type Message } from './protocol.js';

const CONNECT_TIMEOUT_MS = 10_000;

export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly code = 2013,
    readonly sqlstate = 'HY000',
  ) {
    super(message);
  }
}

export interface Greeting {
  serverVersion: string;
  connectionId: number;
  caps: number;
  charset: number;
  status: number;
  nonce: Buffer;
  plugin: string;
}

export function parseGreeting(payload: Buffer): Greeting {
  const r = new Reader(payload);
  const protocol = r.u8();
  if (protocol !== 10) throw new UpstreamError(`unsupported protocol version ${protocol}`);
  const serverVersion = r.nul().toString('utf8');
  const connectionId = r.u32();
  const part1 = r.bytes(8);
  r.u8();
  let caps = r.u16();
  const charset = r.u8();
  const status = r.u16();
  caps |= r.u16() << 16;
  const authLen = r.u8();
  r.bytes(10);
  const part2 = r.bytes(Math.max(13, authLen - 8));
  const plugin = caps & CAP.PLUGIN_AUTH ? r.nul().toString('ascii') : NATIVE;
  // part2 ends with a NUL that is not part of the nonce.
  const nonce = Buffer.concat([part1, part2.subarray(0, part2[part2.length - 1] === 0 ? part2.length - 1 : part2.length)]);
  return { serverVersion, connectionId, caps: caps >>> 0, charset, status, nonce, plugin };
}

/** Reads one message at a time from a socket. */
export class MessageQueue {
  private reader = new PacketReader();
  private queue: Message[] = [];
  private waiters: { resolve: (m: Message) => void; reject: (e: Error) => void }[] = [];
  private error: Error | null = null;
  private readonly onData = (chunk: Buffer) => {
    for (const m of this.reader.push(chunk)) {
      const w = this.waiters.shift();
      if (w) w.resolve(m);
      else this.queue.push(m);
    }
  };
  private readonly onEnd = (err?: Error) => {
    this.error = err ?? new UpstreamError('the database closed the connection');
    for (const w of this.waiters.splice(0)) w.reject(this.error);
  };

  private readonly onClose = () => this.onEnd();

  constructor(public socket: net.Socket) {
    this.attach(socket);
  }

  attach(socket: net.Socket) {
    this.socket = socket;
    socket.on('data', this.onData);
    socket.on('error', this.onEnd);
    socket.on('close', this.onClose);
    socket.resume();
  }

  /** Stops reading (the socket is paused so nothing is lost before the next reader attaches). */
  detach() {
    this.socket.pause();
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onEnd);
    this.socket.off('close', this.onClose);
  }

  next(): Promise<Message> {
    const m = this.queue.shift();
    if (m) return Promise.resolve(m);
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  /** Whatever arrived after the last message handed out (to pass on to the session). */
  leftover(): Buffer {
    const msgs = this.queue.splice(0).map((m) => m.raw);
    return Buffer.concat([...msgs, this.reader.drain()]);
  }
}

export interface UpstreamOptions {
  login: { user: string; password: string };
  /** Capability flags the client and proxy agreed on; the upstream session must use the same. */
  caps: number;
  charset: number;
  attrs: Record<string, string>;
}

export interface Upstream {
  socket: net.Socket;
  greeting: Greeting;
  /** Status flags from the final OK. */
  status: number;
  /** Bytes already received after the handshake. */
  leftover: Buffer;
  /** Run a statement on the connection before it is handed to the session; returns text rows. */
  query(sql: string): Promise<string[][]>;
}

/** Capabilities that change how commands and results are encoded: the server must have every one the client asked for. */
export const SESSION_CAPS = [
  CAP.FOUND_ROWS,
  CAP.LONG_FLAG,
  CAP.IGNORE_SPACE,
  CAP.PROTOCOL_41,
  CAP.TRANSACTIONS,
  CAP.SECURE_CONNECTION,
  CAP.MULTI_STATEMENTS,
  CAP.MULTI_RESULTS,
  CAP.PS_MULTI_RESULTS,
  CAP.PLUGIN_AUTH,
  CAP.SESSION_TRACK,
  CAP.DEPRECATE_EOF,
];

/**
 * Logs in to the real server as the proxy's login, with the client's capabilities and charset.
 * Supports TLS per sslmode, mysql_native_password and caching_sha2_password (fast, or full over
 * TLS / RSA), and auth switches.
 */
export async function connectMysqlUpstream(db: DatabaseConfig, opts: UpstreamOptions): Promise<Upstream> {
  let socket: net.Socket = net.connect({ host: db.host, port: db.port });
  socket.setNoDelay(true);
  const timer = setTimeout(() => socket.destroy(new UpstreamError('timed out connecting to the database')), CONNECT_TIMEOUT_MS);
  const q = new MessageQueue(socket);
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', (e) => reject(new UpstreamError(e.message)));
    });
    const first = await q.next();
    if (first.payload[0] === 0xff) {
      const e = parseErr(first.payload);
      throw new UpstreamError(e.message, e.code, e.sqlstate);
    }
    const greeting = parseGreeting(first.payload);
    for (const cap of SESSION_CAPS) {
      if (opts.caps & cap && !(greeting.caps & cap)) throw new UpstreamError(`the database server lacks a protocol capability (0x${cap.toString(16)}) the client asked for`);
    }

    let seq = 1;
    let secure = false;
    let caps = (opts.caps & ~(CAP.SSL | CAP.CONNECT_ATTRS | CAP.PLUGIN_AUTH_LENENC | CAP.LOCAL_FILES | CAP.COMPRESS)) | CAP.CONNECT_WITH_DB | CAP.PLUGIN_AUTH;
    caps |= greeting.caps & (CAP.CONNECT_ATTRS | CAP.PLUGIN_AUTH_LENENC);
    const wantTls = db.sslmode !== 'disable';
    if (wantTls && !(greeting.caps & CAP.SSL) && db.sslmode !== 'prefer') throw new UpstreamError('the database server does not support TLS (sslmode requires it)');
    if (wantTls && greeting.caps & CAP.SSL) {
      caps |= CAP.SSL;
      socket.write(packet(seq++, handshakeHead(caps, opts.charset)));
      q.detach();
      const secured = tls.connect({ socket, rejectUnauthorized: db.sslmode === 'verify-full', servername: net.isIP(db.host) ? undefined : db.host });
      await new Promise<void>((resolve, reject) => {
        secured.once('secureConnect', resolve);
        secured.once('error', (e) => reject(new UpstreamError(`TLS: ${e.message}`)));
      });
      socket = secured;
      q.attach(secured);
      secure = true;
    }

    const { password, user } = opts.login;
    let plugin = greeting.plugin === NATIVE || greeting.plugin === SHA2 ? greeting.plugin : NATIVE;
    let challenge = greeting.nonce;
    const authData = scramble(plugin, password, challenge);
    const attrs = Buffer.concat(Object.entries(opts.attrs).flatMap(([k, v]) => [lenencBytes(Buffer.from(k)), lenencBytes(Buffer.from(v))]));
    socket.write(
      packet(
        seq++,
        Buffer.concat([
          handshakeHead(caps, opts.charset),
          nulString(user),
          caps & CAP.PLUGIN_AUTH_LENENC ? lenencBytes(authData) : Buffer.concat([Buffer.from([authData.length]), authData]),
          nulString(db.database),
          nulString(plugin),
          caps & CAP.CONNECT_ATTRS ? Buffer.concat([lenencInt(attrs.length), attrs]) : Buffer.alloc(0),
        ]),
      ),
    );

    for (;;) {
      const m = await q.next();
      seq = m.lastSeq + 1;
      const p = m.payload;
      if (p[0] === 0x00) {
        clearTimeout(timer);
        const ok = parseOk(p);
        q.detach();
        return { socket, greeting, status: ok.status, leftover: q.leftover(), query: (sql) => internalQuery(socket, sql, caps) };
      }
      if (p[0] === 0xff) {
        const e = parseErr(p);
        throw new UpstreamError(e.message, e.code, e.sqlstate);
      }
      if (p[0] === 0xfe) {
        // Auth switch: another plugin, a new challenge.
        const r = new Reader(p);
        r.u8();
        plugin = r.nul().toString('ascii');
        const data = r.rest();
        challenge = data[data.length - 1] === 0 ? data.subarray(0, data.length - 1) : data;
        if (plugin === 'mysql_clear_password' && secure) socket.write(packet(seq, nulString(password)));
        else if (plugin === NATIVE || plugin === SHA2) socket.write(packet(seq, scramble(plugin, password, challenge)));
        else throw new UpstreamError(`the database asked for the ${plugin} authentication plugin, which twophase does not support; use mysql_native_password or caching_sha2_password for the proxy's login`);
        continue;
      }
      if (p[0] === 0x01) {
        // caching_sha2: 0x03 = fast auth OK (an OK follows), 0x04 = full auth needed; otherwise a PEM public key.
        if (p.length === 2 && p[1] === 0x03) continue;
        if (p.length === 2 && p[1] === 0x04) {
          socket.write(packet(seq, secure ? nulString(password) : Buffer.from([0x02])));
          continue;
        }
        const pem = p.subarray(1).toString('ascii');
        socket.write(packet(seq, rsaEncryptPassword(password, challenge, pem)));
        continue;
      }
      throw new UpstreamError(`unexpected handshake packet 0x${p[0].toString(16)}`);
    }
  } catch (err) {
    clearTimeout(timer);
    socket.destroy();
    throw err instanceof UpstreamError ? err : new UpstreamError((err as Error).message);
  }
}

function handshakeHead(caps: number, charset: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(caps >>> 0, 0);
  b.writeUInt32LE(16 * 1024 * 1024, 4);
  b[8] = charset;
  return b;
}

/** Runs one text-protocol statement on a connection we own (before the session takes it over). */
async function internalQuery(socket: net.Socket, sql: string, caps: number): Promise<string[][]> {
  const q = new MessageQueue(socket);
  try {
    socket.write(packet(0, Buffer.concat([Buffer.from([COM.QUERY]), Buffer.from(sql, 'utf8')])));
    const first = (await q.next()).payload;
    if (first[0] === 0xff) {
      const e = parseErr(first);
      throw new UpstreamError(e.message, e.code, e.sqlstate);
    }
    if (first[0] === 0x00) return [];
    const columns = new Reader(first).lenenc() ?? 0;
    for (let i = 0; i < columns; i++) await q.next();
    if (!(caps & CAP.DEPRECATE_EOF)) await q.next();
    const rows: string[][] = [];
    for (;;) {
      const m = (await q.next()).payload;
      if (isEof(m)) break;
      if (m[0] === 0xff) {
        const e = parseErr(m);
        throw new UpstreamError(e.message, e.code, e.sqlstate);
      }
      const r = new Reader(m);
      const row: string[] = [];
      for (let i = 0; i < columns; i++) row.push(r.lenencBytes()?.toString('utf8') ?? '');
      rows.push(row);
    }
    return rows;
  } finally {
    q.detach();
  }
}
