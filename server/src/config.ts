import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  /** Built web admin UI to serve at `/`, if present. */
  webDir: string;
  /**
   * `token`: admin API requires ADMIN_TOKEN (or the generated one).
   * `tailscale`: no token; any verified tailnet device reaching us via `tailscale serve` may manage the proxy.
   */
  adminAuth: 'token' | 'tailscale';
  tailscaleSocket: string;
  /** Explicit admin token. When unset, one is generated on first boot and persisted (hashed). */
  adminToken?: string;
  /** Optional management password: adds a sign-in to Tailscale, or replaces token login. */
  adminPassword?: string;
  resetAdminToken: boolean;
  /** How long a statement waits for a human decision before failing. */
  approvalTimeoutSeconds: number;
  /** Postgres wire-protocol listener (psql, apps, ORMs). */
  wire: { enabled: boolean; host: string; port: number; publicPort: number };
  /** MySQL wire-protocol listener (mysql CLI, apps, ORMs) for MySQL and MariaDB databases. */
  mysqlWire: { enabled: boolean; host: string; port: number; publicPort: number };
  /** Days of activity and decided approvals to keep; 0 keeps everything. */
  auditRetentionDays: number;
  /** Web Push (PWA). Keys are generated and persisted on first boot when unset. */
  vapid: { publicKey?: string; privateKey?: string; subject: string };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  if (env.ADMIN_PASSWORD && env.ADMIN_PASSWORD_FILE) throw new Error('Set only one of ADMIN_PASSWORD and ADMIN_PASSWORD_FILE');
  const adminPassword = env.ADMIN_PASSWORD_FILE
    ? readFileSync(env.ADMIN_PASSWORD_FILE, 'utf8').replace(/\r?\n$/, '')
    : env.ADMIN_PASSWORD || undefined;
  if (env.ADMIN_PASSWORD_FILE && !adminPassword) throw new Error('ADMIN_PASSWORD_FILE must contain a password');
  if (adminPassword && Buffer.byteLength(adminPassword) > 1024) throw new Error('Management password must be at most 1024 bytes');
  return {
    host: env.HOST ?? '0.0.0.0',
    port: Number(env.PORT ?? 8787),
    dataDir: env.DATA_DIR ?? './data',
    webDir: env.WEB_DIR ?? fileURLToPath(new URL('../../web/dist', import.meta.url)),
    adminAuth: env.ADMIN_AUTH === 'tailscale' ? 'tailscale' : 'token',
    tailscaleSocket: env.TAILSCALE_SOCKET ?? '/var/run/tailscale/tailscaled.sock',
    adminToken: env.ADMIN_TOKEN || undefined,
    adminPassword,
    resetAdminToken: env.RESET_ADMIN_TOKEN === '1',
    approvalTimeoutSeconds: Number(env.APPROVAL_TIMEOUT_SECONDS ?? 300),
    auditRetentionDays: Number(env.AUDIT_RETENTION_DAYS ?? 90),
    wire: {
      enabled: env.WIRE_ENABLED !== 'false',
      host: env.WIRE_HOST ?? env.HOST ?? '0.0.0.0',
      port: Number(env.WIRE_PORT ?? 6432),
      // Port clients should use (differs when something like `tailscale serve --tcp` fronts it).
      publicPort: Number(env.WIRE_PUBLIC_PORT ?? env.WIRE_PORT ?? 6432),
    },
    mysqlWire: {
      enabled: env.MYSQL_WIRE_ENABLED !== 'false',
      host: env.MYSQL_WIRE_HOST ?? env.WIRE_HOST ?? env.HOST ?? '0.0.0.0',
      port: Number(env.MYSQL_WIRE_PORT ?? 3307),
      publicPort: Number(env.MYSQL_WIRE_PUBLIC_PORT ?? env.MYSQL_WIRE_PORT ?? 3307),
    },
    vapid: {
      publicKey: env.VAPID_PUBLIC_KEY || undefined,
      privateKey: env.VAPID_PRIVATE_KEY || undefined,
      subject: env.VAPID_SUBJECT ?? 'mailto:admin@example.com',
    },
  };
}
