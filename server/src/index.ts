import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const proxy = createApp(config);
const { wirePort } = await proxy.listen();
console.log(`twophase listening on http://${config.host}:${config.port}  (web UI + admin API, hosted MCP at /mcp/<database>)`);
if (wirePort) console.log(`  Postgres clients: postgresql://<client>:<token>@${config.wire.host}:${wirePort}/<database>`);
console.log(`  push: web (VAPID)${config.apns ? ' + APNs' : ''}`);

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.once(sig, async () => {
    await proxy.close();
    process.exit(0);
  });
}
