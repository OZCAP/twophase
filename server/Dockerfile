# Build from the repo root: docker build -f server/Dockerfile .
FROM node:22-slim AS build
WORKDIR /app
COPY server/package*.json server/tsconfig*.json ./server/
COPY web/package*.json ./web/
# better-sqlite3 ships prebuilt binaries for linux x64/arm64 (glibc + musl); skip the implicit
# node-gyp rebuild npm would otherwise run (it needs python + a C++ toolchain).
RUN cd server && npm ci --ignore-scripts && cd ../web && npm ci --ignore-scripts
COPY server/src ./server/src
COPY server/drizzle ./server/drizzle
COPY web ./web
RUN cd server && npm run build && npm prune --omit=dev && cd ../web && npm run build

FROM node:22-slim
WORKDIR /app/server
COPY --from=build /app/server/node_modules ./node_modules
COPY --from=build /app/server/dist ./dist
COPY server/drizzle ./drizzle
COPY --from=build /app/web/dist /app/web/dist
COPY server/package.json ./
# Run as the image's unprivileged `node` user; a new volume at /data inherits this ownership.
RUN mkdir -p /data && chown node:node /data
USER node
ENV DATA_DIR=/data PORT=8787 NODE_ENV=production
VOLUME /data
EXPOSE 8787 6432 3307
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8787) + '/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/index.js"]
