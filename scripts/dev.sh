#!/usr/bin/env bash
# Start CertPilot's local development stack in one terminal.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

gateway_pid=""
core_pid=""
frontend_pid=""

cleanup() {
  trap - EXIT INT TERM
  printf '\nStopping CertPilot development services...\n'

  for pid in "$frontend_pid" "$core_pid" "$gateway_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done

  wait 2>/dev/null || true
}

trap cleanup EXIT INT TERM

printf 'Starting self-signed gateway on :9091...\n'
go run ./gateways/selfsigned/cmd/ --port=9091 --insecure &
gateway_pid=$!

# Let the gateway bind before the core registers it as a plugin.
for _ in {1..300}; do
  if nc -z 127.0.0.1 9091 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! nc -z 127.0.0.1 9091 2>/dev/null; then
  echo 'The self-signed gateway did not start on port 9091.' >&2
  exit 1
fi

printf 'Starting API on :8080...\n'
# With no config.dev.yaml, the core selects its in-memory local-development
# defaults and permits the loopback gateway above without TLS.
go run ./core/cmd/ --config=config.dev.yaml &
core_pid=$!

printf 'Starting frontend on :3000...\n'
(cd frontend && npm run dev) &
frontend_pid=$!

printf '\nCertPilot is running:\n  Frontend: http://127.0.0.1:3000/\n  API:      http://127.0.0.1:8080/healthz\n\nPress Ctrl-C to stop all services.\n\n'

wait
