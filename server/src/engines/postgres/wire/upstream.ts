import { createHash } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import type { DatabaseConfig } from '../../../store.js';
import {
  cancelRequest,
  FrameReader,
  parseFields,
  passwordMessage,
  Reader,
  saslInitialResponse,
  saslResponse,
  sslRequest,
  startupMessage,
  type Frame,
} from './protocol.js';
import { ScramClientSession } from './scram.js';

export interface UpstreamConnection {
  socket: net.Socket;
  /** Raw ParameterStatus messages from the server's startup, to replay to the client. */
  parameterStatus: Buffer[];
  backendKey: { pid: number; secret: number };
  /** Bytes received after the startup ReadyForQuery (normally none). */
  leftover: Buffer;
}

export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly sqlstate: string = '08006',
  ) {
    super(message);
  }
}

const md5 = (s: string | Buffer) => createHash('md5').update(s).digest('hex');

async function openSocket(db: Pick<DatabaseConfig, 'host' | 'port' | 'sslmode'>): Promise<net.Socket> {
  const raw = net.connect({ host: db.host, port: db.port });
  raw.setNoDelay(true);
  raw.setKeepAlive(true, 30_000);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new UpstreamError(`timed out connecting to ${db.host}:${db.port}`)), 10_000);
    raw.once('connect', () => (clearTimeout(timer), resolve()));
    raw.once('error', (e) => (clearTimeout(timer), reject(new UpstreamError(`could not connect to ${db.host}:${db.port}: ${e.message}`))));
  });
  if (db.sslmode === 'disable') return raw;

  raw.write(sslRequest());
  const answer = await new Promise<string>((resolve, reject) => {
    raw.once('data', (d) => resolve(String.fromCharCode(d[0])));
    raw.once('error', reject);
  });
  if (answer !== 'S') {
    if (db.sslmode === 'prefer') return raw;
    raw.destroy();
    throw new UpstreamError(`server at ${db.host}:${db.port} does not support SSL, but sslmode=${db.sslmode}`);
  }
  const secure = tls.connect({ socket: raw, servername: net.isIP(db.host) ? undefined : db.host, rejectUnauthorized: db.sslmode === 'verify-full' });
  await new Promise<void>((resolve, reject) => {
    secure.once('secureConnect', resolve);
    secure.once('error', (e) => reject(new UpstreamError(`TLS handshake with ${db.host} failed: ${e.message}`)));
  });
  return secure;
}

/** Reads messages from a socket during the handshake. */
function handshakeReader(socket: net.Socket) {
  const reader = new FrameReader();
  const waiting: ((f: Frame) => void)[] = [];
  let failure: Error | null = null;
  const pump = () => {
    let f: Frame | null;
    while (waiting.length && (f = reader.next())) waiting.shift()!(f);
  };
  const onData = (d: Buffer) => {
    reader.push(d);
    pump();
  };
  const onEnd = () => {
    failure = new UpstreamError('server closed the connection during startup');
    while (waiting.length) waiting.shift()!({ type: '\0', body: Buffer.alloc(0), raw: Buffer.alloc(0) });
  };
  socket.on('data', onData);
  socket.once('close', onEnd);
  return {
    next: () =>
      new Promise<Frame>((resolve, reject) => {
        if (failure) return reject(failure);
        const f = reader.next();
        if (f) return resolve(f);
        waiting.push((frame) => (failure ? reject(failure) : resolve(frame)));
      }),
    detach: () => {
      socket.off('data', onData);
      socket.off('close', onEnd);
      return reader.drain();
    },
  };
}

/**
 * Opens a session to the real database as the proxy's own login, performing TLS and SCRAM/md5
 * authentication, and returns the socket positioned right after the first ReadyForQuery.
 */
export async function connectUpstream(
  db: Pick<DatabaseConfig, 'host' | 'port' | 'sslmode' | 'database'>,
  login: { user: string; password: string },
  params: Record<string, string>,
): Promise<UpstreamConnection> {
  const socket = await openSocket(db);
  const hs = handshakeReader(socket);
  try {
    socket.write(startupMessage({ ...params, user: login.user, database: db.database }));
    const parameterStatus: Buffer[] = [];
    let backendKey = { pid: 0, secret: 0 };
    let scram: ScramClientSession | null = null;

    for (;;) {
      const f = await hs.next();
      if (f.type === 'E') {
        const e = parseFields(f.body);
        throw new UpstreamError(e.get('M') ?? 'upstream error', e.get('C') ?? '08006');
      }
      if (f.type === 'R') {
        const r = new Reader(f.body);
        const kind = r.int32();
        if (kind === 0) continue; // AuthenticationOk
        if (kind === 3) socket.write(passwordMessage(login.password));
        else if (kind === 5) socket.write(passwordMessage(`md5${md5(Buffer.concat([Buffer.from(md5(login.password + login.user)), r.bytes(4)]))}`));
        else if (kind === 10) {
          const mechanisms: string[] = [];
          for (let m = r.cstring(); m; m = r.cstring()) mechanisms.push(m);
          if (!mechanisms.includes('SCRAM-SHA-256')) throw new UpstreamError(`unsupported SASL mechanisms: ${mechanisms.join(', ')}`);
          scram = new ScramClientSession(login.password);
          socket.write(saslInitialResponse('SCRAM-SHA-256', scram.first()));
        } else if (kind === 11) socket.write(saslResponse(scram!.final(f.body.subarray(4).toString('utf8'))));
        else if (kind === 12) {
          if (!scram!.verify(f.body.subarray(4).toString('utf8'))) throw new UpstreamError('server signature mismatch during SCRAM authentication');
        } else throw new UpstreamError(`unsupported authentication method ${kind}`);
        continue;
      }
      if (f.type === 'S') parameterStatus.push(Buffer.from(f.raw));
      else if (f.type === 'K') {
        const r = new Reader(f.body);
        backendKey = { pid: r.int32(), secret: r.int32() };
      } else if (f.type === 'Z') {
        return { socket, parameterStatus, backendKey, leftover: hs.detach() };
      }
      // NoticeResponse ('N') and NegotiateProtocolVersion ('v') during startup are ignored.
    }
  } catch (err) {
    hs.detach();
    socket.destroy();
    throw err instanceof UpstreamError ? err : new UpstreamError((err as Error).message);
  }
}

/** Forwards a cancel to the real server using its backend key. */
export async function sendUpstreamCancel(db: Pick<DatabaseConfig, 'host' | 'port' | 'sslmode'>, key: { pid: number; secret: number }) {
  const socket = await openSocket(db).catch(() => null);
  if (!socket) return;
  socket.end(cancelRequest(key.pid, key.secret));
  socket.on('error', () => {});
  setTimeout(() => socket.destroy(), 2000).unref();
}
