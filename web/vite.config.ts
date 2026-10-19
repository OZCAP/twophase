import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const target = process.env.PROXY_URL ?? 'http://localhost:8787';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/admin/api': { target, changeOrigin: true },
      '/mcp': { target, changeOrigin: true },
    },
  },
});
