import type { DatabaseConfig } from '../store.js';
import { MysqlExecutor } from './mysql/executor.js';
import { PostgresExecutor } from './postgres/executor.js';
import type { Executor } from './types.js';

export type Engine = DatabaseConfig['engine'];
/** Engines that speak the same wire protocol share a listener. */
export type Protocol = 'postgres' | 'mysql';

export const protocolOf = (engine: Engine): Protocol => (engine === 'postgres' ? 'postgres' : 'mysql');

export const ENGINE_LABELS: Record<Engine, string> = { postgres: 'Postgres', mysql: 'MySQL', mariadb: 'MariaDB' };

export const DEFAULT_PORTS: Record<Engine, number> = { postgres: 5432, mysql: 3306, mariadb: 3306 };

/** One executor per database, rebuilt when its connection settings change. */
export class ExecutorRegistry {
  private executors = new Map<string, Executor & { db: DatabaseConfig }>();

  get(db: DatabaseConfig): Executor {
    const existing = this.executors.get(db.id);
    if (existing && sameConnection(existing.db, db)) {
      Object.assign(existing.db, db);
      return existing;
    }
    void existing?.close();
    const fresh = protocolOf(db.engine) === 'postgres' ? new PostgresExecutor({ ...db }) : new MysqlExecutor({ ...db });
    this.executors.set(db.id, fresh);
    return fresh;
  }

  postgres(db: DatabaseConfig): PostgresExecutor {
    const e = this.get(db);
    if (!(e instanceof PostgresExecutor)) throw new Error(`${db.slug} is not a Postgres database`);
    return e;
  }

  mysql(db: DatabaseConfig): MysqlExecutor {
    const e = this.get(db);
    if (!(e instanceof MysqlExecutor)) throw new Error(`${db.slug} is not a MySQL/MariaDB database`);
    return e;
  }

  async drop(id: string) {
    await this.executors.get(id)?.close();
    this.executors.delete(id);
  }

  async closeAll() {
    await Promise.all([...this.executors.values()].map((e) => e.close()));
    this.executors.clear();
  }
}

function sameConnection(a: DatabaseConfig, b: DatabaseConfig) {
  return (
    a.engine === b.engine &&
    a.host === b.host &&
    a.port === b.port &&
    a.database === b.database &&
    a.user === b.user &&
    a.password === b.password &&
    a.sslmode === b.sslmode
  );
}
