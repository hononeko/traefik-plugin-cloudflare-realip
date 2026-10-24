#!/usr/bin/env bash
# Loads the plugin into a real Traefik and checks the headers that reach the backend. A plugin that fails to load
# disables every plugin in that Traefik, so this is the check that matters before a release.
set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose -p realip-e2e "$@"; }
trap 'status=$?; [ "$status" -ne 0 ] && compose logs traefik; compose down -v >/dev/null 2>&1; exit "$status"' EXIT

compose up -d --quiet-pull

for _ in $(seq 1 30); do
  curl -fsS -o /dev/null http://127.0.0.1:18443/ 2>/dev/null && break
  sleep 1
done
# Captured first: grep -q closing the pipe early would fail the pipeline under pipefail.
logs=$(compose logs traefik 2>&1)
if ! grep -q 'Plugins loaded' <<<"$logs"; then
  echo "Traefik didn't load the plugin" >&2
  exit 1
fi

fail=0
# expect <port> <header> <want> [curl header args...]
expect() {
  local port=$1 header=$2 want=$3 got
  shift 3
  got=$(curl -fsS "$@" "http://127.0.0.1:$port/" | tr -d '\r' | sed -n "s/^$header: //p")
  if [ "$got" = "$want" ]; then
    echo "ok   :$port $header = '$got'"
  else
    echo "FAIL :$port $header = '$got', want '$want'"
    fail=1
  fi
}

forged=(
  -H 'X-Forwarded-For: 192.168.1.244' -H 'X-Real-Ip: 192.168.1.244' -H 'Forwarded: for=192.168.1.244'
  -H 'Cf-Connecting-Ip: 203.0.113.7'
)
# Published ports reach Traefik from the Docker network's gateway, the peer Traefik appends to X-Forwarded-For.
gateway=$(docker network inspect realip-e2e_default -f '{{(index .IPAM.Config 0).Gateway}}')

# Trusted peer: CF-Connecting-IP replaces every forged value.
expect 18443 X-Real-Ip 203.0.113.7 "${forged[@]}"
expect 18443 X-Forwarded-For "203.0.113.7, $gateway" "${forged[@]}"
expect 18443 Cf-Connecting-Ip 203.0.113.7 "${forged[@]}"
expect 18443 Forwarded "" "${forged[@]}"

# Trusted peer claiming a private client: ignored, the peer is the client.
expect 18443 X-Real-Ip "$gateway" -H 'Cf-Connecting-Ip: 192.168.1.10'

# Peer the entrypoint trusts but the plugin doesn't: the peer is the client, whatever the entrypoint kept.
expect 18001 X-Real-Ip "$gateway" "${forged[@]}"
expect 18001 X-Forwarded-For "$gateway, $gateway" "${forged[@]}"
expect 18001 Cf-Connecting-Ip "" "${forged[@]}"

# Without the plugin the forged values reach the backend, which is the problem the plugin solves.
expect 18000 X-Real-Ip 192.168.1.244 "${forged[@]}"

exit "$fail"
