#!/usr/bin/env bash
# tools/replay_auth_log.sh
# ─────────────────────────────────────────────────────────────────
# Replay a local auth.log file into the ingestion service.
# Each line is sent as a separate event (linux-auth source).
#
# Usage:
#   ./tools/replay_auth_log.sh                           # uses sample_logs/auth.log
#   ./tools/replay_auth_log.sh /var/log/auth.log
#   ./tools/replay_auth_log.sh /var/log/auth.log myhost
#
# Requirements: bash, curl
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

LOG_FILE="${1:-sample_logs/auth.log}"
HOST_NAME="${2:-replay-host}"
INGEST_URL="${INGESTION_URL:-http://localhost:8001}/ingest"

if [ ! -f "$LOG_FILE" ]; then
  echo "Error: log file not found: $LOG_FILE" >&2
  exit 1
fi

LINE_COUNT=$(wc -l < "$LOG_FILE")
echo "Replaying $LINE_COUNT lines from $LOG_FILE → $INGEST_URL"
echo "Host label: $HOST_NAME"
echo ""

SUCCESS=0
SKIPPED=0
ERRORS=0

while IFS= read -r line; do
  [ -z "$line" ] && continue

  # Escape quotes in the line for JSON embedding
  ESCAPED=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')

  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$INGEST_URL" \
    -H "Content-Type: application/json" \
    -d "{\"source\": \"linux-auth\", \"payload\": {\"line\": \"$ESCAPED\", \"host\": \"$HOST_NAME\"}}" \
    2>/dev/null || echo -e "\n000")

  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  BODY=$(echo "$RESPONSE" | head -1)

  if [ "$HTTP_CODE" = "200" ]; then
    STATUS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
    if [ "$STATUS" = "ok" ]; then
      SUCCESS=$((SUCCESS + 1))
      printf "  ✓ %s\n" "${line:0:80}"
    else
      SKIPPED=$((SKIPPED + 1))
      printf "  ~ (skipped) %s\n" "${line:0:60}"
    fi
  else
    ERRORS=$((ERRORS + 1))
    printf "  ✗ HTTP %s: %s\n" "$HTTP_CODE" "${line:0:60}" >&2
    if [ "$HTTP_CODE" = "000" ]; then
      echo "  → Cannot connect. Is the ingestion service running at $INGEST_URL?" >&2
      exit 1
    fi
  fi

  # Small delay to avoid hammering SQLite
  sleep 0.05

done < "$LOG_FILE"

echo ""
echo "────────────────────────────────────────"
echo "  Done."
echo "  Ingested:  $SUCCESS"
echo "  Skipped:   $SKIPPED  (unrecognized lines)"
echo "  Errors:    $ERRORS"
echo "────────────────────────────────────────"
echo ""
echo "Open http://localhost:8080 to see the results."
