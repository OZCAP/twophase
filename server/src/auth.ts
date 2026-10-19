import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';
import { createVerifier } from './engines/postgres/wire/scram.js';
import type { MysqlVerifier, Store } from './store.js';

export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');

export function generateToken(kind: 'client' | 'admin'): { token: string; hash: string; prefix: string } {
  const token = `${kind === 'client' ? 'tp' : 'tpa'}_${randomBytes(24).toString('base64url')}`;
  return { token, hash: hashToken(token), prefix: token.slice(0, 12) };
}

const sha = (alg: 'sha1' | 'sha256', data: Buffer | string) => createHash(alg).update(data).digest();

/** What a MySQL server stores to check a password: SHA1(SHA1(pw)) (mysql_native_password) and SHA256(SHA256(pw)) (caching_sha2_password fast auth). */
export function mysqlVerifier(token: string): MysqlVerifier {
  return { mysqlNativeHash: sha('sha1', sha('sha1', token)).toString('hex'), mysqlSha2Hash: sha('sha256', sha('sha256', token)).toString('hex') };
}

/** A client token plus everything stored about it: its hash (MCP bearer auth), a SCRAM verifier (Postgres logins) and MySQL verifiers. */
export function issueClientToken() {
  const { token, hash, prefix } = generateToken('client');
  return { token, stored: { tokenHash: hash, tokenPrefix: prefix, ...createVerifier(token), ...mysqlVerifier(token) } };
}

/** Postgres login name for a client: lowercase, [a-z0-9_], unique (suffix added on clash). */
export function usernameFor(name: string, taken: (u: string) => boolean): string {
  const base = name.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 50) || 'client';
  let candidate = base;
  for (let i = 2; taken(candidate); i++) candidate = `${base}_${i}`;
  return candidate;
}

export function bearerToken(req: Request): string | null {
  const h = req.header('authorization');
  const m = h?.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Tailscale mode has no admin token; drop any stored one so previously issued tokens stop working. */
export function forgetAdminToken(store: Store) {
  store.deleteSetting('admin_token_hash');
}

/**
 * Resolves the admin token hash. ADMIN_TOKEN wins; otherwise a token is generated on
 * first boot (or with RESET_ADMIN_TOKEN=1), printed once, and only its hash is kept.
 */
export function resolveAdminTokenHash(store: Store, opts: { adminToken?: string; reset: boolean }): string {
  if (opts.adminToken) return hashToken(opts.adminToken);
  const stored = store.getSetting('admin_token_hash');
  if (stored && !opts.reset) return stored;
  const { token, hash } = generateToken('admin');
  store.setSetting('admin_token_hash', hash);
  console.log(`\n  Admin token (shown once, sign in to the web app with it):\n\n    ${token}\n`);
  return hash;
}
