import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const target = process.env.PROXY_URL ?? 'http://localhost:8787';
const buildTime = new Date().toISOString();

export default defineConfig({
  plugins: [
    react(),
    // The open app compares this with its own build when it comes back to the foreground, and reloads if it is stale.
    {
      name: 'version-json',
      generateBundle() {
        this.emitFile({ type: 'asset', fileName: 'version.json', source: JSON.stringify({ build: buildTime }) });
      },
    },
  ],
  // Shown in Settings, so you can tell whether "Refresh app" picked up a new version.
  define: { __BUILD_TIME__: JSON.stringify(buildTime) },
  server: {
    proxy: {
      '/admin/api': { target, changeOrigin: false },
      '/mcp': { target, changeOrigin: true },
    },
  },
});
