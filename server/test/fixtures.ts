/** Public dummy credentials for disposable local containers only. Never read app credentials. */
export const FIXTURE_DATABASE_URLS = Object.freeze({
  PG_TEST_URL: 'postgresql://mcptest:mcptest@127.0.0.1:55432/shop',
  MYSQL_TEST_URL: 'mysql://root:roottest@127.0.0.1:53306/mysql',
  MARIADB_TEST_URL: 'mysql://root:roottest@127.0.0.1:53307/mysql',
});

/** Reject the whole URL: query parameters can override driver hosts and credentials too. */
export function assertFixtureDatabaseEnvironment(env: NodeJS.ProcessEnv): void {
  for (const [name, expected] of Object.entries(FIXTURE_DATABASE_URLS)) {
    if (env[name] !== undefined && env[name] !== expected) {
      // Do not include the supplied value: it might contain real credentials.
      throw new Error(`${name} overrides are disabled. Tests only use the documented disposable local database containers.`);
    }
  }
}

assertFixtureDatabaseEnvironment(process.env);
