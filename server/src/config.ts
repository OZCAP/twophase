import { fileURLToPath } from 'node:url';

export interface ApnsConfig {
  keyId: string;
  teamId: string;
  keyPath: string;
  bundleId: string;
}

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  /** Built web admin UI to serve at `/`, if present. */
  webDir: string;
  /**
   * `token`: admin API requires ADMIN_TOKEN (or the generated one).
   * `tailscale`: no token; the caller's tailnet device (via `tailscale serve`) must match `tailscaleAllow`.
   */
  adminAuth: 'token' | 'tailscale';
  /** Devices allowed to administer in tailscale mode: `tag:…`, `user@provider`, or machine names. */
  tailscaleAllow: string[];
  tailscaleSocket: string;
  /** Explicit admin token. When unset, one is generated on first boot and persisted (hashed). */
  adminToken?: string;
  resetAdminToken: boolean;
  /** How long a statement waits for a human decision before failing. */
  approvalTimeoutSeconds: number;
  /** Postgres wire-protocol listener (psql, apps, ORMs). */
  wire: { enabled: boolean; host: string; port: number; publicPort: number };
  /** Web Push (PWA). Keys are generated and persisted on first boot when unset. */
  vapid: { publicKey?: string; privateKey?: string; subject: string };
  apns: ApnsConfig | null;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const apns =
    env.APNS_KEY_ID && env.APNS_TEAM_ID && env.APNS_KEY_PATH && env.APNS_BUNDLE_ID
      ? {
          keyId: env.APNS_KEY_ID,
          teamId: env.APNS_TEAM_ID,
          keyPath: env.APNS_KEY_PATH,
          bundleId: env.APNS_BUNDLE_ID,
        }
      : null;

  return {
    host: env.HOST ?? '0.0.0.0',
    port: Number(env.PORT ?? 8787),
    dataDir: env.DATA_DIR ?? './data',
    webDir: env.WEB_DIR ?? fileURLToPath(new URL('../../web/dist', import.meta.url)),
    adminAuth: env.ADMIN_AUTH === 'tailscale' ? 'tailscale' : 'token',
    tailscaleAllow: (env.ADMIN_TAILSCALE_ALLOW ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    tailscaleSocket: env.TAILSCALE_SOCKET ?? '/var/run/tailscale/tailscaled.sock',
    adminToken: env.ADMIN_TOKEN || undefined,
    resetAdminToken: env.RESET_ADMIN_TOKEN === '1',
    approvalTimeoutSeconds: Number(env.APPROVAL_TIMEOUT_SECONDS ?? 300),
    wire: {
      enabled: env.WIRE_ENABLED !== 'false',
      host: env.WIRE_HOST ?? env.HOST ?? '0.0.0.0',
      port: Number(env.WIRE_PORT ?? 6432),
      // Port clients should use (differs when something like `tailscale serve --tcp` fronts it).
      publicPort: Number(env.WIRE_PUBLIC_PORT ?? env.WIRE_PORT ?? 6432),
    },
    vapid: {
      publicKey: env.VAPID_PUBLIC_KEY || undefined,
      privateKey: env.VAPID_PRIVATE_KEY || undefined,
      subject: env.VAPID_SUBJECT ?? 'mailto:admin@example.com',
    },
    apns,
  };
}
