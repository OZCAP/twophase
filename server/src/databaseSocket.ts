import http from 'node:http';
import net from 'node:net';
import { Duplex } from 'node:stream';

/** Userspace tailscaled does not install OS routes or a MagicDNS resolver. */
export function isTailnetHost(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  if (name.endsWith('.ts.net')) return true;
  if (net.isIPv4(name)) {
    const [a, b] = name.split('.').map(Number);
    return a === 100 && b >= 64 && b <= 127;
  }
  return net.isIPv6(name) && name.startsWith('fd7a:115c:a1e0:');
}

function tailnetSocket(host: string): string | undefined {
  return isTailnetHost(host) ? process.env.TAILSCALE_SOCKET || undefined : undefined;
}

/** Dial through the sidecar's identity, including its MagicDNS and ACL enforcement. */
function dialTailnet(host: string, port: number, socketPath: string, signal?: AbortSignal): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath, method: 'POST', path: '/localapi/v0/dial', agent: false, signal,
      headers: {
        Host: 'local-tailscaled.sock', Connection: 'upgrade', Upgrade: 'ts-dial',
        'Dial-Host': host, 'Dial-Port': String(port), 'Content-Length': '0',
      },
    });
    const timer = setTimeout(() => request.destroy(new Error(`Tailscale connection to ${host}:${port} timed out`)), 10_000);
    request.once('error', (error) => { clearTimeout(timer); reject(error); });
    request.once('response', (response) => {
      clearTimeout(timer);
      response.destroy();
      reject(new Error(`Tailscale could not connect to ${host}:${port} (HTTP ${response.statusCode})`));
    });
    request.once('upgrade', (response, socket, head) => {
      clearTimeout(timer);
      if (response.statusCode !== 101) {
        socket.destroy();
        reject(new Error(`Tailscale dial refused (HTTP ${response.statusCode})`));
        return;
      }
      // Preserve greetings coalesced with the HTTP upgrade (notably MySQL).
      socket.pause();
      if (head.length) socket.unshift(head);
      resolve(socket as net.Socket);
    });
    request.end();
  });
}

/** Raw TCP only; the database drivers still perform their usual TLS/authentication. */
export function openDatabaseSocket(host: string, port: number): Promise<net.Socket> {
  const path = tailnetSocket(host);
  if (path) return dialTailnet(host, port, path);
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => socket.destroy(new Error(`Connection to ${host}:${port} timed out`)), 10_000);
    const onError = (error: Error) => { clearTimeout(timer); reject(error); };
    socket.once('error', onError);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.off('error', onError);
      resolve(socket);
    });
  });
}

/** pg and mysql2 require a synchronous stream factory, before the async dial completes. */
class TailnetStream extends Duplex {
  connecting = true;
  private socket?: net.Socket;
  private readonly abort = new AbortController();
  private readonly ready: Promise<net.Socket>;
  private noDelay = true;
  private keepAlive: [boolean, number] = [false, 0];

  constructor(host: string, port: number, path: string) {
    super();
    // Both drivers install their error/data handlers synchronously after creating the stream.
    this.ready = Promise.resolve().then(() => dialTailnet(host, port, path, this.abort.signal)).then((socket) => {
      this.socket = socket;
      if (this.destroyed) { socket.destroy(); throw new Error('Connection closed during Tailscale dial'); }
      socket.setNoDelay(this.noDelay);
      socket.setKeepAlive(...this.keepAlive);
      socket.on('data', (data: Buffer) => { if (!this.push(data)) socket.pause(); });
      socket.once('end', () => this.push(null));
      socket.once('error', (error) => this.destroy(error));
      socket.once('close', () => this.destroy());
      this.connecting = false;
      this.emit('connect');
      socket.resume();
      return socket;
    });
    void this.ready.catch((error: Error) => this.destroy(error));
  }

  connect() { return this; }
  setNoDelay(value = true) { this.noDelay = value; this.socket?.setNoDelay(value); return this; }
  setKeepAlive(value = false, delay = 0) { this.keepAlive = [value, delay]; this.socket?.setKeepAlive(value, delay); return this; }
  ref() { this.socket?.ref(); return this; }
  unref() { this.socket?.unref(); return this; }
  override _read() { this.socket?.resume(); }
  override _write(chunk: Buffer, encoding: BufferEncoding, callback: (error?: Error | null) => void) {
    void this.ready.then((socket) => { socket.write(chunk, encoding, callback); }, callback);
  }
  override _final(callback: (error?: Error | null) => void) {
    void this.ready.then((socket) => { socket.end(callback); }, callback);
  }
  override _destroy(error: Error | null, callback: (error: Error | null) => void) {
    this.abort.abort();
    this.socket?.destroy();
    callback(error);
  }
}

export function databaseStream(host: string, port: number): (() => Duplex) | undefined {
  const path = tailnetSocket(host);
  return path ? () => new TailnetStream(host, port, path) : undefined;
}
