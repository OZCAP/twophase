import http from 'node:http';
import type { Request } from 'express';

export interface TailscaleIdentity {
  ip: string;
  /** Short machine name, e.g. `iphone-13-pro` */
  node: string;
  tags: string[];
  /** Owner login for user-owned devices (e.g. `alice@github`); null for tagged devices. */
  login: string | null;
}

export type Whois = (ip: string) => Promise<TailscaleIdentity | null>;

const CACHE_MS = 60_000;

/** Asks the local tailscaled (LocalAPI over its unix socket) which tailnet device owns an IP. */
export function localApiWhois(socketPath: string): Whois {
  const cache = new Map<string, { at: number; identity: TailscaleIdentity | null }>();

  const lookup = (ip: string) =>
    new Promise<TailscaleIdentity | null>((resolve, reject) => {
      const req = http.get(
        {
          socketPath,
          path: `/localapi/v0/whois?addr=${encodeURIComponent(ip)}`,
          headers: { Host: 'local-tailscaled.sock' },
          timeout: 3000,
        },
        (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', (c) => (body += c));
          res.on('end', () => {
            if (res.statusCode === 404) return resolve(null);
            if (res.statusCode !== 200) return reject(new Error(`tailscaled whois ${res.statusCode}: ${body.slice(0, 200)}`));
            const d = JSON.parse(body);
            const tags: string[] = d.Node?.Tags ?? [];
            resolve({
              ip,
              node: String(d.Node?.Name ?? '').split('.')[0],
              tags,
              login: tags.length ? null : (d.UserProfile?.LoginName ?? null),
            });
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('tailscaled whois timed out')));
      req.on('error', reject);
    });

  return async (ip) => {
    const hit = cache.get(ip);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.identity;
    const identity = await lookup(ip);
    cache.set(ip, { at: Date.now(), identity });
    return identity;
  };
}

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

/**
 * The caller's tailnet IP as reported by `tailscale serve`, which proxies from loopback and
 * overwrites any client-supplied X-Forwarded-For. Anything not arriving via loopback is ignored.
 */
export function tailnetCallerIp(req: Request): string | null {
  if (!LOOPBACK.has(req.socket.remoteAddress ?? '')) return null;
  const xff = req.header('x-forwarded-for');
  return xff ? xff.split(',').at(-1)!.trim() : null;
}
