#!/bin/sh
# Entrypoint for the Tailscale container in docker-compose.yml.
# Writes the serve config with the HTTPS port from TS_HTTPS_PORT (default 443), then runs the
# given command (containerboot). The web app, admin API and hosted MCP are served on that port.
set -eu

port="${TS_HTTPS_PORT:-443}"
case "$port" in
  '' | *[!0-9]*) echo "tailscale-start: TS_HTTPS_PORT must be a port number, got '$port'" >&2; exit 1 ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  echo "tailscale-start: TS_HTTPS_PORT must be between 1 and 65535, got $port" >&2; exit 1
fi
if [ "$port" = 6432 ] || [ "$port" = 3307 ]; then
  echo "tailscale-start: TS_HTTPS_PORT $port is already used for database clients" >&2; exit 1
fi

template="${TS_SERVE_TEMPLATE:-/config/tailscale-serve.json}"
rendered=/tmp/tailscale-serve.json
# The template is the plain 443 config; swap in the chosen port.
sed -e "s/\"443\":/\"$port\":/" -e "s/}:443\"/}:$port\"/" "$template" > "$rendered"
grep -q "\"$port\": { \"HTTPS\": true }" "$rendered" || {
  echo "tailscale-start: couldn't set port $port in $template" >&2; exit 1
}
export TS_SERVE_CONFIG="$rendered"

exec "$@"
