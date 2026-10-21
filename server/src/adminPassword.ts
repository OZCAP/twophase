import { randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { hashToken } from './auth.js';
import type { Store } from './store.js';
import { tailnetCallerIp } from './tailscaleAuth.js';

const COOKIE = 'twophase-management';
const LIFETIME = 30 * 24 * 60 * 60_000;
const MAX_SESSIONS = 256;
const KDF = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
type Session = { hash: string; expires: number; caller: string };

/** Passwords never leave this verifier; only hashes of random session tokens are persisted. */
export class AdminPassword {
  private readonly salt: Buffer;
  private readonly expected: Buffer;
  private sessions: Session[] = [];
  private failures = new Map<string, { count: number; until: number }>();
  private verifying = 0;
  private readonly listeners = new Set<() => void>();

  constructor(password: string, private readonly store: Store) {
    const stored = store.getSetting('admin_password_verifier');
    const [salt, hash] = stored?.split(':') ?? [];
    this.salt = salt && /^[0-9a-f]{32}$/.test(salt) ? Buffer.from(salt, 'hex') : randomBytes(16);
    this.expected = scryptSync(password, this.salt, 32, KDF);
    const verifier = `${this.salt.toString('hex')}:${this.expected.toString('hex')}`;
    if (hash && stored === verifier) {
      try { this.sessions = JSON.parse(store.getSetting('admin_password_sessions') ?? '[]'); }
      catch { this.sessions = []; }
    }
    store.setSetting('admin_password_verifier', verifier);
    this.persist();
  }

  private persist() {
    this.sessions = this.sessions.filter((session) => session.expires > Date.now()).slice(-MAX_SESSIONS);
    this.store.setSetting('admin_password_sessions', JSON.stringify(this.sessions));
  }

  private caller(req: Request): string {
    return tailnetCallerIp(req) ?? req.socket.remoteAddress ?? 'unknown';
  }

  private token(req: Request): string | undefined {
    return req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
  }

  session(req: Request): Session | undefined {
    const token = this.token(req);
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return;
    const hash = hashToken(token);
    return this.sessions.find((session) => session.hash === hash && session.expires > Date.now() && session.caller === this.caller(req));
  }

  /** Cookies cannot authorize a cross-site form or fetch, including requests without Origin. */
  sameOrigin(req: Request): boolean {
    if (req.header('sec-fetch-site') === 'cross-site') return false;
    const origin = req.header('origin');
    if (!origin) return req.header('sec-fetch-site') === 'same-origin' || req.method === 'GET' || req.method === 'HEAD' || req.header('content-type')?.split(';')[0].trim() === 'application/json';
    try { return new URL(origin).host === req.get('host'); }
    catch { return false; }
  }

  private setCookie(req: Request, res: Response, value: string, maxAge: number) {
    // tailscale serve terminates TLS on loopback; only trust its forwarded scheme from loopback.
    const local = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '');
    const localName = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(req.hostname.toLowerCase());
    // Network hostnames always get Secure cookies, including TLS proxies on a Docker bridge.
    const secure = !localName || req.secure || (local && req.header('x-forwarded-proto') === 'https');
    res.cookie(COOKIE, value, { httpOnly: true, secure, sameSite: 'strict', path: '/admin/api', maxAge });
  }

  async login(req: Request, res: Response): Promise<void> {
    if (!this.sameOrigin(req)) { res.status(403).json({ error: 'Sign in from this site' }); return; }
    const key = this.caller(req);
    for (const [caller, attempt] of this.failures) if (attempt.until <= Date.now()) this.failures.delete(caller);
    const attempt = this.failures.get(key);
    if ((attempt?.count ?? 0) >= 5 || this.verifying >= 2 || this.failures.size >= 1024) {
      res.setHeader('Retry-After', '60');
      res.status(429).json({ error: 'Too many sign-in attempts. Try again in a minute.' });
      return;
    }
    const password = req.body?.password;
    if (typeof password !== 'string' || Buffer.byteLength(password) > 1024) {
      res.status(400).json({ error: 'Enter a password of at most 1024 bytes' });
      return;
    }
    // Count before awaiting: simultaneous attempts cannot race past the per-caller limit.
    this.failures.set(key, { count: (attempt?.count ?? 0) + 1, until: attempt?.until ?? Date.now() + 60_000 });
    this.verifying++;
    let actual: Buffer;
    try {
      actual = await new Promise<Buffer>((resolve, reject) => scrypt(password, this.salt, 32, KDF, (error, derived) => error ? reject(error) : resolve(derived)));
    } finally { this.verifying--; }
    if (!timingSafeEqual(actual, this.expected)) {
      res.status(401).json({ error: 'Incorrect password', code: 'password_required' });
      return;
    }
    this.failures.delete(key);
    const token = randomBytes(32).toString('base64url');
    const old = this.session(req);
    if (old) this.sessions = this.sessions.filter((session) => session !== old);
    this.sessions.push({ hash: hashToken(token), expires: Date.now() + LIFETIME, caller: key });
    this.persist();
    for (const listener of this.listeners) listener();
    this.setCookie(req, res, token, LIFETIME);
    res.status(204).end();
  }

  logout(req: Request, res: Response) {
    const token = this.token(req);
    if (token) this.sessions = this.sessions.filter((session) => session.hash !== hashToken(token));
    this.persist();
    this.setCookie(req, res, '', 0);
    for (const listener of this.listeners) listener();
    res.status(204).end();
  }

  /** SSE streams must stop delivering data when their session expires or is revoked. */
  watch(req: Request, res: Response): () => void {
    let timer: ReturnType<typeof setTimeout>;
    const check = () => {
      clearTimeout(timer);
      const session = this.session(req);
      if (!session) { res.end(); return; }
      // Node timers cannot exceed ~24.8 days. Re-arm until the 30-day session expires.
      timer = setTimeout(check, Math.max(1, Math.min(session.expires - Date.now(), 2 ** 31 - 1)));
    };
    this.listeners.add(check);
    check();
    return () => { clearTimeout(timer); this.listeners.delete(check); };
  }
}
