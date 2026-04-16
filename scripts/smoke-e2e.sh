#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend-dashboard"

BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:5173}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[smoke-e2e] Command '$1' is not available."
    exit 1
  fi
}

require_cmd curl
require_cmd npm

if [[ ! -d "$FRONTEND_DIR" ]]; then
  echo "[smoke-e2e] frontend-dashboard directory not found."
  exit 1
fi

echo "[smoke-e2e] Checking backend health at ${BACKEND_URL}/health/live"
curl -fsS "${BACKEND_URL}/health/live" >/dev/null

echo "[smoke-e2e] Checking frontend dev server at ${FRONTEND_URL}"
curl -fsS "${FRONTEND_URL}" >/dev/null

echo "[smoke-e2e] Running smoke API call from frontend context"
(
  cd "$FRONTEND_DIR"
  VITE_API_BASE_URL="$BACKEND_URL" npm run smoke:predict-v2
)

echo "[smoke-e2e] Success: frontend and backend are connected"
