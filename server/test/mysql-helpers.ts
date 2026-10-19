import { randomBytes } from 'node:crypto';
import mysql from 'mysql2/promise';
import type { TestProxy } from './helpers.js';

export type Flavour = 'mysql' | 'mariadb';

const range = (n: number) => Array.from({ length: n }, (_, i) => i + 1);

/** Root connections to the throwaway test servers (see README → Development). */
export const MYSQL_ADMIN_URL: Record<Flavour, string> = {
  mysql: process.env.MYSQL_TEST_URL ?? 'mysql://root:roottest@127.0.0.1:53306/mysql',
  mariadb: process.env.MARIADB_TEST_URL ?? 'mysql://root:roottest@127.0.0.1:53307/mysql',
};

export async function mysqlAvailable(flavour: Flavour): Promise<boolean> {
  try {
    const c = await mysql.createConnection({ uri: MYSQL_ADMIN_URL[flavour], connectTimeout: 2000 });
    await c.end();
    return true;
  } catch {
    return false;
  }
}

/**
 * A fresh database with the shop schema and a login that only has privileges on it, the way
 * the proxy should run in production.
 */
export async function createMysqlTestDatabase(flavour: Flavour) {
  const suffix = randomBytes(4).toString('hex');
  const database = `proxytest_${suffix}`;
  const user = `proxy_${suffix}`;
  const password = randomBytes(12).toString('hex');
  const url = new URL(MYSQL_ADMIN_URL[flavour]);
  const root = await mysql.createConnection({ uri: MYSQL_ADMIN_URL[flavour], multipleStatements: true });
  await root.query(`CREATE DATABASE ${database}`);
  await root.query(`CREATE USER '${user}'@'%' IDENTIFIED BY '${password}'`);
  await root.query(
    `GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, TRIGGER, REFERENCES ON ${database}.* TO '${user}'@'%'`,
  );
  await root.query(`USE ${database}`);
  await root.query(`
    CREATE TABLE customers (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(200) UNIQUE NOT NULL, name VARCHAR(200) NOT NULL) COMMENT 'People who buy things';
    CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, customer_id INT, total_cents INT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'paid',
                         FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE TABLE secrets (id INT PRIMARY KEY, value TEXT);
    INSERT INTO customers (email, name) VALUES ${range(20).map((n) => `('user${n}@example.com', 'Customer ${n}')`).join(', ')};
    INSERT INTO orders (customer_id, total_cents) VALUES ${range(50).map((n) => `(${1 + (n % 20)}, ${100 * n})`).join(', ')};
    INSERT INTO secrets VALUES (1, 'hunter2');
    CREATE FUNCTION order_total(c INT) RETURNS BIGINT READS SQL DATA RETURN (SELECT SUM(total_cents) FROM orders WHERE customer_id = c);
    CREATE FUNCTION bump_order(o INT) RETURNS INT DETERMINISTIC BEGIN UPDATE orders SET total_cents = total_cents + 1 WHERE id = o; RETURN 1; END;
  `);

  return {
    flavour,
    database,
    user,
    password,
    host: url.hostname,
    port: Number(url.port),
    /** Direct (not proxied) root access, to check what really happened. */
    direct: root,
    sql: async <T = any>(q: string, params?: unknown[]) => (await root.query(q, params))[0] as T[],
    async drop() {
      await root.query(`DROP DATABASE IF EXISTS ${database}`);
      await root.query(`DROP USER IF EXISTS '${user}'@'%'`);
      await root.end();
    },
  };
}

export type MysqlTestDatabase = Awaited<ReturnType<typeof createMysqlTestDatabase>>;

/** Registers a MySQL/MariaDB test database and one client with MCP + wire access. */
export async function seedMysql(proxy: TestProxy, tdb: MysqlTestDatabase, slug = 'shop') {
  const db = await proxy.admin('POST', '/databases', {
    slug,
    name: 'Shop',
    engine: tdb.flavour,
    host: tdb.host,
    port: tdb.port,
    database: tdb.database,
    user: tdb.user,
    password: tdb.password,
    sslmode: 'disable',
  });
  const client = await proxy.admin('POST', '/users', { name: 'agent', access: [{ databaseId: db.id, allowMcp: true, allowWire: true }] });
  return { db, client: client as { user: any; token: string } };
}
