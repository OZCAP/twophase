import { constants, createHash, publicEncrypt, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * MySQL password authentication. Both plugins are challenge–response over a 20-byte nonce, and
 * the server only needs a double hash of the password to check the reply:
 *   mysql_native_password:  reply = SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw)))
 *   caching_sha2_password:  reply = SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + nonce)   ("fast auth")
 * We store those double hashes per client (see auth.ts → mysqlVerifier), so fast auth always
 * succeeds and no client ever needs to send its token in clear.
 */

export const NATIVE = 'mysql_native_password';
export const SHA2 = 'caching_sha2_password';

const sha1 = (...parts: Buffer[]) => createHash('sha1').update(Buffer.concat(parts)).digest();
const sha256 = (...parts: Buffer[]) => createHash('sha256').update(Buffer.concat(parts)).digest();
const xor = (a: Buffer, b: Buffer) => Buffer.from(a.map((v, i) => v ^ b[i % b.length]));

/** A 20-byte nonce of printable, non-NUL bytes (some clients treat it as a C string). */
export function nonce(): Buffer {
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&()*+,-./:;<=>?[]^_{|}~';
  return Buffer.from([...randomBytes(20)].map((b) => alphabet.charCodeAt(b % alphabet.length)));
}

/** Server side: does `reply` prove knowledge of the password whose double hash is `stored` (hex)? */
export function verifyScramble(plugin: string, stored: string | undefined, challenge: Buffer, reply: Buffer): boolean {
  if (!stored) return false;
  const doubleHash = Buffer.from(stored, 'hex');
  if (plugin === NATIVE) {
    if (reply.length !== 20 || doubleHash.length !== 20) return false;
    const candidate = xor(reply, sha1(challenge, doubleHash));
    return timingSafeEqual(sha1(candidate), doubleHash);
  }
  if (plugin === SHA2) {
    if (reply.length !== 32 || doubleHash.length !== 32) return false;
    const candidate = xor(reply, sha256(doubleHash, challenge));
    return timingSafeEqual(sha256(candidate), doubleHash);
  }
  return false;
}

/** Client side: the reply for a plugin's challenge. */
export function scramble(plugin: string, password: string, challenge: Buffer): Buffer {
  if (password === '') return Buffer.alloc(0);
  const pw = Buffer.from(password, 'utf8');
  if (plugin === NATIVE) {
    const stage1 = sha1(pw);
    return xor(stage1, sha1(challenge, sha1(stage1)));
  }
  if (plugin === SHA2) {
    const stage1 = sha256(pw);
    return xor(stage1, sha256(sha256(stage1), challenge));
  }
  throw new Error(`unsupported authentication plugin ${plugin}`);
}

/** caching_sha2 / sha256 full authentication without TLS: the password, XORed with the nonce, RSA-OAEP encrypted. */
export function rsaEncryptPassword(password: string, challenge: Buffer, pem: string): Buffer {
  const data = xor(Buffer.concat([Buffer.from(password, 'utf8'), Buffer.from([0])]), challenge);
  return publicEncrypt({ key: pem, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);
}
