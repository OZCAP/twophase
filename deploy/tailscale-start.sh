#!/bin/sh
# Entrypoint for the Tailscale container in docker-compose.yml.
# Writes the `tailscale serve` config, then runs the given command (containerboot).
#
#   TS_HTTPS_PORT  web app and admin API, plus hosted MCP unless TS_MCP_PORT is set (default 443)
#   TS_MCP_PORT    optional: serve hosted MCP on this port only (the app listens on 8788 for it)
#
# Database clients always use 6432 (Postgres) and 3307 (MySQL / MariaDB).
set -eu

fail() { echo "tailscale-start: $*" >&2; exit 1; }

check_port() { # name value
  case "$2" in
    '' | *[!0-9]*) fail "$1 must be a port number, got '$2'" ;;
  esac
  [ "$2" -ge 1 ] && [ "$2" -le 65535 ] || fail "$1 must be between 1 and 65535, got $2"
  [ "$2" != 6432 ] && [ "$2" != 3307 ] || fail "$1 $2 is already used for database clients"
}

ui_port="${TS_HTTPS_PORT:-443}"
mcp_port="${TS_MCP_PORT:-}"
check_port TS_HTTPS_PORT "$ui_port"
if [ -n "$mcp_port" ]; then
  check_port TS_MCP_PORT "$mcp_port"
  [ "$mcp_port" != "$ui_port" ] || fail "TS_MCP_PORT must differ from TS_HTTPS_PORT; leave it unset to serve MCP on $ui_port"
fi

# containerboot fills in ${TS_CERT_DOMAIN}.
web() { # port backend
  printf '    "${TS_CERT_DOMAIN}:%s": { "Handlers": { "/": { "Proxy": "%s" } } }' "$1" "$2"
}

config=/tmp/tailscale-serve.json
{
  echo '{'
  echo '  "TCP": {'
  printf '    "%s": { "HTTPS": true },\n' "$ui_port"
  [ -z "$mcp_port" ] || printf '    "%s": { "HTTPS": true },\n' "$mcp_port"
  echo '    "6432": { "TCPForward": "127.0.0.1:6432" },'
  echo '    "3307": { "TCPForward": "127.0.0.1:3307" }'
  echo '  },'
  echo '  "Web": {'
  web "$ui_port" http://127.0.0.1:8787
  if [ -n "$mcp_port" ]; then
    echo ','
    web "$mcp_port" http://127.0.0.1:8788
  fi
  echo
  echo '  }'
  echo '}'
} > "$config"
export TS_SERVE_CONFIG="$config"

exec "$@"
