import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * SCRAM-SHA-256 (RFC 5802 / 7677) as Postgres uses it, without channel binding.
 * Server side: authenticates proxy clients against a stored verifier (the token never crosses
 * the wire and isn't stored). Client side: logs the proxy in to the real database.
 */

export const SCRAM_ITERATIONS = 4096;

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest();
const hmac = (key: Buffer, msg: string) => createHmac('sha256', key).update(msg).digest();
const xor = (a: Buffer, b: Buffer) => Buffer.from(a.map((v, i) => v ^ b[i]));

export interface ScramVerifier {
  scramSalt: string;
  scramIterations: number;
  scramStoredKey: string;
  scramServerKey: string;
}

function saltedPassword(password: string, salt: Buffer, iterations: number) {
  // Postgres applies SASLprep; proxy tokens and typical passwords are ASCII, where it is the identity.
  return pbkdf2Sync(password.normalize('NFKC'), salt, iterations, 32, 'sha256');
}

export function createVerifier(password: string, iterations = SCRAM_ITERATIONS): ScramVerifier {
  const salt = randomBytes(16);
  const salted = saltedPassword(password, salt, iterations);
  return {
    scramSalt: salt.toString('base64'),
    scramIterations: iterations,
    scramStoredKey: sha256(hmac(salted, 'Client Key')).toString('base64'),
    scramServerKey: hmac(salted, 'Server Key').toString('base64'),
  };
}

/** A verifier no password matches, used for unknown usernames so they can't be probed. */
export function dummyVerifier(): ScramVerifier {
  return createVerifier(randomBytes(32).toString('base64'), SCRAM_ITERATIONS);
}

const attrs = (msg: string) => new Map(msg.split(',').map((kv) => [kv.slice(0, 1), kv.slice(2)] as const));

export class ScramServerSession {
  private clientFirstBare = '';
  private serverFirst = '';
  private nonce = '';
  private gs2Header = '';

  constructor(private verifier: ScramVerifier) {}

  /** Handles client-first-message, returns server-first-message. Throws on malformed input. */
  first(clientFirst: string): string {
    const m = /^([nyp])(=[^,]*)?,(a=[^,]*)?,(.*)$/.exec(clientFirst);
    if (!m) throw new Error('malformed SCRAM client-first-message');
    if (m[1] === 'p') throw new Error('SCRAM channel binding is not supported');
    this.gs2Header = clientFirst.slice(0, clientFirst.length - m[4].length);
    this.clientFirstBare = m[4];
    const clientNonce = attrs(this.clientFirstBare).get('r');
    if (!clientNonce) throw new Error('SCRAM nonce missing');
    this.nonce = clientNonce + randomBytes(18).toString('base64');
    this.serverFirst = `r=${this.nonce},s=${this.verifier.scramSalt},i=${this.verifier.scramIterations}`;
    return this.serverFirst;
  }

  /** Verifies client-final-message; returns server-final-message, or null if the proof is wrong. */
  final(clientFinal: string): string | null {
    const proofIdx = clientFinal.lastIndexOf(',p=');
    if (proofIdx < 0) return null;
    const withoutProof = clientFinal.slice(0, proofIdx);
    const a = attrs(withoutProof);
    if (a.get('r') !== this.nonce) return null;
    if (a.get('c') !== Buffer.from(this.gs2Header).toString('base64')) return null;
    const proof = Buffer.from(clientFinal.slice(proofIdx + 3), 'base64');
    const authMessage = `${this.clientFirstBare},${this.serverFirst},${withoutProof}`;
    const storedKey = Buffer.from(this.verifier.scramStoredKey, 'base64');
    if (proof.length !== storedKey.length) return null;
    const clientKey = xor(proof, hmac(storedKey, authMessage));
    if (!timingSafeEqual(sha256(clientKey), storedKey)) return null;
    const serverSignature = hmac(Buffer.from(this.verifier.scramServerKey, 'base64'), authMessage);
    return `v=${serverSignature.toString('base64')}`;
  }
}

export class ScramClientSession {
  private clientNonce = randomBytes(18).toString('base64');
  private clientFirstBare = `n=,r=${this.clientNonce}`;
  private serverSignature: Buffer | null = null;

  constructor(private password: string) {}

  first(): string {
    return `n,,${this.clientFirstBare}`;
  }

  /** Given server-first-message, returns client-final-message. */
  final(serverFirst: string): string {
    const a = attrs(serverFirst);
    const nonce = a.get('r');
    const salt = a.get('s');
    const iterations = Number(a.get('i'));
    if (!nonce?.startsWith(this.clientNonce) || !salt || !iterations) throw new Error('invalid SCRAM server-first-message');
    const salted = saltedPassword(this.password, Buffer.from(salt, 'base64'), iterations);
    const clientKey = hmac(salted, 'Client Key');
    const withoutProof = `c=biws,r=${nonce}`;
    const authMessage = `${this.clientFirstBare},${serverFirst},${withoutProof}`;
    const proof = xor(clientKey, hmac(sha256(clientKey), authMessage));
    this.serverSignature = hmac(hmac(salted, 'Server Key'), authMessage);
    return `${withoutProof},p=${proof.toString('base64')}`;
  }

  /** Verifies the server knew the password too. */
  verify(serverFinal: string): boolean {
    const v = attrs(serverFinal).get('v');
    return !!v && !!this.serverSignature && timingSafeEqual(Buffer.from(v, 'base64'), this.serverSignature);
  }
}
