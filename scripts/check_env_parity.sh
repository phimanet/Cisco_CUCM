#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-/opt/cucm-web}"
SERVICE_NAME="${2:-cucm-web}"

if [[ ! -d "$APP_DIR" ]]; then
  echo "ERROR: app directory not found: $APP_DIR" >&2
  exit 1
fi

echo "=== CUCM Web Parity Check ==="
echo "Host: $(hostname -f 2>/dev/null || hostname)"
echo "Date: $(date -Iseconds)"
echo "App dir: $APP_DIR"
echo "Service: $SERVICE_NAME"

echo
echo "--- Git ---"
cd "$APP_DIR"
git rev-parse --short HEAD
git log -1 --oneline

echo
echo "--- Service ---"
systemctl is-active "$SERVICE_NAME" || true
systemctl status "$SERVICE_NAME" --no-pager | sed -n '1,12p'

echo
echo "--- Key Flags (.env) ---"
if [[ -f "$APP_DIR/.env" ]]; then
  grep -E '^(SMS_NUMBER_LOOKUP_ENABLED|TWILIO_HOSTED_NUMBERS_ACTIVE|PREVIEW_FEATURES_LAB_ONLY_DEFAULT|SMS_EXPERIMENTAL_MENU_ENABLED|SMS_EXPERIMENTAL_MENU_LAB_ONLY|INTEGRATION_PREFLIGHT_REQUIRED)=' "$APP_DIR/.env" || echo "No tracked flags found in .env"
else
  echo ".env not found in $APP_DIR"
fi

echo
echo "--- Health ---"
HEALTH_OK=0
for i in {1..20}; do
  if curl -fsS "http://127.0.0.1:8000/healthz" >/dev/null 2>&1; then
    curl -fsS "http://127.0.0.1:8000/healthz"
    HEALTH_OK=1
    break
  fi

  if curl -ksS "https://127.0.0.1/healthz" >/dev/null 2>&1; then
    curl -ksS "https://127.0.0.1/healthz"
    HEALTH_OK=1
    break
  fi

  sleep 1
done

if [[ "$HEALTH_OK" -ne 1 ]]; then
  echo "Could not reach /healthz via localhost:8000 or local nginx https endpoint after retry window"
fi

echo
echo "Parity check complete."
