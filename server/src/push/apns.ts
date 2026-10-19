import http2 from 'node:http2';
import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { ApnsConfig } from '../config.js';
import type { Store } from '../store.js';

const HOSTS = {
  production: 'https://api.push.apple.com',
  sandbox: 'https://api.sandbox.push.apple.com',
} as const;

/** Sends APNs alerts to the native iOS app (not built yet). Only constructed when APNS_* is configured. */
export class ApnsSender {
  private key: KeyObject;
  private jwt: { token: string; issuedAt: number } | null = null;
  private sessions = new Map<string, http2.ClientHttp2Session>();

  constructor(
    private store: Store,
    private cfg: ApnsConfig,
  ) {
    this.key = createPrivateKey(readFileSync(cfg.keyPath));
  }

  async sendToAll(payload: object, headers: Record<string, string>) {
    await Promise.all(
      this.store.listApnsDevices().map((d) =>
        this.send(d.token, d.environment, payload, headers).catch((err) =>
          console.warn(`[apns] ${d.token.slice(0, 8)}…: ${err.message}`),
        ),
      ),
    );
  }

  private bearer(): string {
    const nowS = Math.floor(Date.now() / 1000);
    // Apple rejects tokens older than 1h and throttles refreshes more often than every 20 min.
    if (this.jwt && nowS - this.jwt.issuedAt < 50 * 60) return this.jwt.token;
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${b64({ alg: 'ES256', kid: this.cfg.keyId })}.${b64({ iss: this.cfg.teamId, iat: nowS })}`;
    const sig = sign('sha256', Buffer.from(unsigned), { key: this.key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    this.jwt = { token: `${unsigned}.${sig}`, issuedAt: nowS };
    return this.jwt.token;
  }

  private session(env: keyof typeof HOSTS): http2.ClientHttp2Session {
    let s = this.sessions.get(env);
    if (!s || s.closed || s.destroyed) {
      s = http2.connect(HOSTS[env]);
      s.on('error', () => this.sessions.delete(env));
      s.on('close', () => this.sessions.delete(env));
      s.unref();
      this.sessions.set(env, s);
    }
    return s;
  }

  private send(token: string, env: keyof typeof HOSTS, payload: object, headers: Record<string, string>) {
    return new Promise<void>((resolve, reject) => {
      const req = this.session(env).request({
        ':method': 'POST',
        ':path': `/3/device/${token}`,
        authorization: `bearer ${this.bearer()}`,
        'apns-topic': this.cfg.bundleId,
        'apns-push-type': 'alert',
        'apns-priority': '10',
        ...headers,
      });
      let status = 0;
      let body = '';
      req.setEncoding('utf8');
      req.on('response', (h) => (status = Number(h[':status'])));
      req.on('data', (c) => (body += c));
      req.on('error', reject);
      req.on('end', () => {
        if (status === 200) return resolve();
        if (status === 410 || body.includes('BadDeviceToken')) this.store.deleteApnsDevice(token);
        reject(new Error(`APNs ${status} ${body}`));
      });
      req.end(JSON.stringify(payload));
    });
  }

  close() {
    for (const s of this.sessions.values()) s.close();
  }
}
