import { fileURLToPath } from 'node:url';

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
  /** MySQL wire-protocol listener (mysql CLI, apps, ORMs) for MySQL and MariaDB databases. */
  mysqlWire: { enabled: boolean; host: string; port: number; publicPort: number };
  /** Days of activity and decided approvals to keep; 0 keeps everything. */
  auditRetentionDays: number;
  /** Hours between database backups into DATA_DIR/backups; 0 turns them off. */
  backupIntervalHours: number;
  /** How many backups to keep. */
  backupKeep: number;
  /** Web Push (PWA). Keys are generated and persisted on first boot when unset. */
  vapid: { publicKey?: string; privateKey?: string; subject: string };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
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
    auditRetentionDays: Number(env.AUDIT_RETENTION_DAYS ?? 90),
    backupIntervalHours: Number(env.BACKUP_INTERVAL_HOURS ?? 24),
    backupKeep: Math.max(1, Number(env.BACKUP_KEEP ?? 7)),
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
