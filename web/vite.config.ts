import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const target = process.env.PROXY_URL ?? 'http://localhost:8787';

export default defineConfig({
  plugins: [react()],
  // Shown in Settings, so you can tell whether "Refresh app" picked up a new version.
  define: { __BUILD_TIME__: JSON.stringify(new Date().toISOString()) },
  server: {
    proxy: {
      '/admin/api': { target, changeOrigin: true },
      '/mcp': { target, changeOrigin: true },
    },
  },
});
