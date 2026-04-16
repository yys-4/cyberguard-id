#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend-dashboard"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

BACKEND_STARTED_BY_SCRIPT=0
BACKEND_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[dev-stack] Command '$1' is not available."
    exit 1
  fi
}

is_port_in_use() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

find_free_port() {
  local port="$1"
  while is_port_in_use "$port"; do
    port=$((port + 1))
  done
  echo "$port"
}

backend_health_ok() {
  local port="$1"
  curl -fsS "http://${BACKEND_HOST}:${port}/health/live" >/dev/null 2>&1
}

wait_backend_ready() {
  local port="$1"
  curl -fsS --retry 40 --retry-all-errors --retry-delay 0 --retry-max-time 20 \
    "http://${BACKEND_HOST}:${port}/health/live" >/dev/null
}

cleanup() {
  if [[ "$BACKEND_STARTED_BY_SCRIPT" -eq 1 && -n "$BACKEND_PID" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

require_cmd curl
require_cmd npm
require_cmd lsof

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[dev-stack] Python venv not found at $PYTHON_BIN"
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR" ]]; then
  echo "[dev-stack] frontend-dashboard directory not found."
  exit 1
fi

if backend_health_ok "$BACKEND_PORT"; then
  echo "[dev-stack] Backend already running at http://${BACKEND_HOST}:${BACKEND_PORT}"
else
  if is_port_in_use "$BACKEND_PORT"; then
    BACKEND_PORT="$(find_free_port "$((BACKEND_PORT + 1))")"
  fi

  echo "[dev-stack] Starting backend at http://${BACKEND_HOST}:${BACKEND_PORT}"
  (
    cd "$ROOT_DIR"
    "$PYTHON_BIN" -m uvicorn src.app:app --host "$BACKEND_HOST" --port "$BACKEND_PORT"
  ) > "$ROOT_DIR/logs/dev-backend.log" 2>&1 &

  BACKEND_PID="$!"
  BACKEND_STARTED_BY_SCRIPT=1
  wait_backend_ready "$BACKEND_PORT"
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
  echo "[dev-stack] Installing frontend dependencies..."
  (
    cd "$FRONTEND_DIR"
    npm install
  )
fi

if is_port_in_use "$FRONTEND_PORT"; then
  FRONTEND_PORT="$(find_free_port "$((FRONTEND_PORT + 1))")"
fi

export VITE_API_BASE_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"

echo "[dev-stack] Backend URL : ${VITE_API_BASE_URL}"
echo "[dev-stack] Frontend URL: http://${FRONTEND_HOST}:${FRONTEND_PORT}"
echo "[dev-stack] Press Ctrl+C to stop."

cd "$FRONTEND_DIR"
npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT"
