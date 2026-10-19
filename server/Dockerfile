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
ENV DATA_DIR=/data PORT=8787
VOLUME /data
EXPOSE 8787 6432
CMD ["node", "dist/index.js"]
