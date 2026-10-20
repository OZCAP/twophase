import { createApp } from './app.js';
import { loadConfig } from './config.js';

// Everything the proxy writes (database, WAL, backups) is private to its own user.
process.umask(0o077);

const config = loadConfig();
const proxy = createApp(config);
const { wirePort, mysqlWirePort } = await proxy.listen();
console.log(`twophase listening on http://${config.host}:${config.port}  (web UI + admin API, hosted MCP at /mcp/<database>)`);
if (wirePort) console.log(`  Postgres clients: postgresql://<client>:<token>@${config.wire.host}:${wirePort}/<database>`);
if (mysqlWirePort) console.log(`  MySQL / MariaDB clients: mysql -h ${config.mysqlWire.host} -P ${mysqlWirePort} -u <client> -p <database>`);
console.log('  push: web (VAPID)');

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.once(sig, async () => {
    await proxy.close();
    process.exit(0);
  });
}
