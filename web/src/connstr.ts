import { DEFAULT_PORT, type Database, type Engine } from './api';

export interface ParsedConnection {
  engine: Engine;
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  sslmode: Database['sslmode'] | null;
  /** Things in the string we couldn't carry over exactly. */
  notes: string[];
}

const SCHEMES: Record<string, Engine> = {
  postgres: 'postgres',
  postgresql: 'postgres',
  mysql: 'mysql',
  mysql2: 'mysql',
  'mysql+pymysql': 'mysql',
  'mysql+mysqldb': 'mysql',
  'postgresql+psycopg': 'postgres',
  'postgresql+psycopg2': 'postgres',
  'postgresql+asyncpg': 'postgres',
  mariadb: 'mariadb',
  'mariadb+mariadbconnector': 'mariadb',
};

/** libpq sslmode → ours. verify-ca has no exact equivalent: require encrypts without checking the certificate. */
const PG_SSL: Record<string, Database['sslmode']> = {
  disable: 'disable',
  allow: 'prefer',
  prefer: 'prefer',
  require: 'require',
  'verify-ca': 'require',
  'verify-full': 'verify-full',
};

/** MySQL ssl-mode → ours. */
const MYSQL_SSL: Record<string, Database['sslmode']> = {
  disabled: 'disable',
  preferred: 'prefer',
  required: 'require',
  verify_ca: 'require',
  verify_identity: 'verify-full',
};

const truthy = (v: string) => /^(1|true|yes|on|required?)$/i.test(v);

function sslFromParams(engine: Engine, params: URLSearchParams, notes: string[]): Database['sslmode'] | null {
  if (engine === 'postgres') {
    const mode = params.get('sslmode')?.toLowerCase();
    if (mode) {
      if (mode === 'verify-ca') notes.push('sslmode=verify-ca is used as "require" (no certificate check); pick verify-full to check it.');
      return PG_SSL[mode] ?? null;
    }
    if (params.has('ssl')) return truthy(params.get('ssl')!) ? 'require' : 'disable';
    return null;
  }
  const mode = (params.get('ssl-mode') ?? params.get('sslmode') ?? params.get('ssl_mode'))?.toLowerCase().replace(/-/g, '_');
  if (mode) {
    if (mode === 'verify_ca') notes.push('ssl-mode=VERIFY_CA is used as "require" (no certificate check); pick verify-full to check it.');
    return MYSQL_SSL[mode] ?? null;
  }
  // PlanetScale: sslaccept=strict; Prisma: sslaccept=strict|accept_invalid_certs.
  const accept = params.get('sslaccept')?.toLowerCase();
  if (accept) return accept === 'strict' ? 'verify-full' : 'require';
  const ssl = params.get('ssl');
  if (ssl) {
    // mysql2: ssl={"rejectUnauthorized":true}, or a profile name such as "Amazon RDS".
    if (/rejectUnauthorized"?\s*:\s*false/i.test(ssl)) return 'require';
    if (/^(0|false|no|off)$/i.test(ssl)) return 'disable';
    return 'verify-full';
  }
  return null;
}

/** libpq keyword/value form: `host=db port=5432 dbname=app user=me password='p w'`. */
function parseKeywordValue(input: string): ParsedConnection | null {
  const pairs = [...input.matchAll(/(\w+)\s*=\s*('(?:\\.|[^'\\])*'|\S+)/g)];
  if (pairs.length === 0) return null;
  const kv = new Map(pairs.map(([, k, v]) => [k.toLowerCase(), v.startsWith("'") ? v.slice(1, -1).replace(/\\(.)/g, '$1') : v]));
  if (!kv.has('host') && !kv.has('hostaddr') && !kv.has('dbname')) return null;
  const notes: string[] = [];
  const params = new URLSearchParams();
  if (kv.has('sslmode')) params.set('sslmode', kv.get('sslmode')!);
  const user = kv.get('user') ?? '';
  return {
    engine: 'postgres',
    host: kv.get('host') ?? kv.get('hostaddr') ?? '',
    port: Number(kv.get('port') ?? DEFAULT_PORT.postgres),
    database: kv.get('dbname') ?? user,
    user,
    password: kv.get('password') ?? '',
    sslmode: sslFromParams('postgres', params, notes),
    notes,
  };
}

/**
 * Parses a connection string into the editor's fields. Accepts URLs (`postgresql://…`,
 * `mysql://…`, `mariadb://…`, also with a `jdbc:` prefix or SQLAlchemy driver suffix) and libpq's
 * `key=value` form. Throws with a readable message when it can't.
 */
export function parseConnectionString(raw: string, fallbackEngine: Engine): ParsedConnection {
  const input = raw.trim().replace(/^jdbc:/i, '');
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(input)?.[1].toLowerCase();
  if (!scheme) {
    const kv = parseKeywordValue(input);
    if (kv) return kv;
    throw new Error('Not a connection string: expected something like postgresql://user:password@host:5432/dbname');
  }
  const engine = SCHEMES[scheme];
  if (!engine) throw new Error(`Unsupported scheme "${scheme}://": use postgresql://, mysql:// or mariadb://`);

  const rest = input.slice(scheme.length + 3);
  const authority = rest.split(/[/?#]/)[0];
  if (authority.slice(authority.lastIndexOf('@') + 1).includes(',')) throw new Error('Multiple hosts are not supported; use a single host.');

  // `new URL` only fully parses special schemes; swap in http to get host/port/credentials parsed.
  let url: URL;
  try {
    url = new URL(`http://${rest}`);
  } catch {
    throw new Error('Could not read that connection string. Check for unencoded characters such as @, / or # in the password.');
  }
  if (!url.hostname) throw new Error('The connection string has no host.');
  const notes: string[] = [];
  const decode = (s: string) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };
  const user = decode(url.username);
  let database = decode(url.pathname.replace(/^\//, '').split('/')[0]);
  if (!database && engine === 'postgres') database = user;
  if (!database) notes.push('No database name in the string: fill it in below.');
  // MySQL ships `mysql://` for MariaDB too; keep a MariaDB choice the user already made.
  const resolved: Engine = engine === 'mysql' && fallbackEngine === 'mariadb' ? 'mariadb' : engine;
  return {
    engine: resolved,
    host: url.hostname.replace(/^\[|\]$/g, ''),
    port: url.port ? Number(url.port) : DEFAULT_PORT[resolved],
    database,
    user,
    password: decode(url.password),
    sslmode: sslFromParams(resolved, url.searchParams, notes),
    notes,
  };
}

/** A name for the database from its host / db name (`orders-db.internal` / `app` → "App"). */
export function suggestName(p: Pick<ParsedConnection, 'database' | 'host'>): string {
  const base = p.database || p.host.split('.')[0] || 'Database';
  return base.charAt(0).toUpperCase() + base.slice(1);
}
