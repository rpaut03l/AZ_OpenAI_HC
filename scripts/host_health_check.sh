#!/bin/bash
# Checks port 80, port 443, SSL cert validity for each host.
# Writes /tmp/health_results.json
# Exits 1 if any host is degraded (makes GHA step go red)

set -euo pipefail

HOSTS_FILE="${1:-scripts/hosts.json}"
OUTPUT_FILE="/tmp/health_results.json"

WARN_DAYS=$(jq -r     '.thresholds.ssl_warn_days'         "$HOSTS_FILE")
CRITICAL_DAYS=$(jq -r '.thresholds.ssl_critical_days'     "$HOSTS_FILE")
TIMEOUT=$(jq -r       '.thresholds.port_timeout_seconds'  "$HOSTS_FILE")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  HOST HEALTH CHECK"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

results='[]'

while IFS= read -r entry; do
  name=$(echo "$entry" | jq -r '.name')
  host=$(echo "$entry" | jq -r '.host')
  env=$(echo  "$entry" | jq -r '.env')

  echo ""
  echo "🔍 Checking: $name ($host)"

  port80="closed"; port443="closed"
  ssl_status="UNKNOWN"; ssl_expiry=""; ssl_days_left="null"
  ssl_subject=""; ssl_issuer=""
  issues='[]'

  # ── Port 80 ────────────────────────────────────────────────────────────────
  echo -n "   Port 80  → "
  if nc -z -w"$TIMEOUT" "$host" 80 2>/dev/null; then
    port80="open"
    echo "✅ OPEN"
  else
    port80="closed"
    echo "❌ CLOSED"
    issues=$(echo "$issues" | jq '. + ["port_80_closed"]')
  fi

  # ── Port 443 ───────────────────────────────────────────────────────────────
  echo -n "   Port 443 → "
  if nc -z -w"$TIMEOUT" "$host" 443 2>/dev/null; then
    port443="open"
    echo "✅ OPEN"

    # ── SSL/TLS certificate check ───────────────────────────────────────────
    echo -n "   SSL/TLS  → "
    cert_output=$(echo | timeout 10 openssl s_client \
      -connect "$host:443" \
      -servername "$host" \
      -verify_quiet 2>/dev/null) || true

    cert_dates=$(echo "$cert_output" | openssl x509 -noout \
      -dates -subject -issuer 2>/dev/null) || true

    if [ -z "$cert_dates" ]; then
      ssl_status="HANDSHAKE_FAILED"
      echo "❌ TLS handshake failed"
      issues=$(echo "$issues" | jq '. + ["ssl_handshake_failed"]')
    else
      ssl_expiry=$(echo  "$cert_dates" | grep notAfter  | cut -d= -f2)
      ssl_subject=$(echo "$cert_dates" | grep subject   | sed 's/subject=//')
      ssl_issuer=$(echo  "$cert_dates" | grep issuer    | sed 's/issuer=//')

      # Cross-platform epoch (Linux GHA runner always uses GNU date)
      expiry_epoch=$(date -d "$ssl_expiry" +%s 2>/dev/null || echo "0")
      now_epoch=$(date +%s)
      ssl_days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

      if   [ "$ssl_days_left" -lt 0 ]; then
        ssl_status="EXPIRED"
        echo "💀 EXPIRED ($ssl_days_left days ago)"
        issues=$(echo "$issues" | jq '. + ["ssl_expired"]')
      elif [ "$ssl_days_left" -lt "$CRITICAL_DAYS" ]; then
        ssl_status="CRITICAL"
        echo "🔴 CRITICAL — expires in ${ssl_days_left} days"
        issues=$(echo "$issues" | jq ". + [\"ssl_critical_${ssl_days_left}d\"]")
      elif [ "$ssl_days_left" -lt "$WARN_DAYS" ]; then
        ssl_status="WARNING"
        echo "⚠️  WARNING — expires in ${ssl_days_left} days"
        issues=$(echo "$issues" | jq ". + [\"ssl_warning_${ssl_days_left}d\"]")
      else
        ssl_status="VALID"
        echo "✅ VALID — expires in ${ssl_days_left} days (${ssl_expiry})"
      fi

      echo "   Subject   → $ssl_subject"
      echo "   Issuer    → $ssl_issuer"
    fi
  else
    port443="closed"
    ssl_status="SKIPPED"
    echo "❌ CLOSED"
    echo "   SSL/TLS  → ⏭️  SKIPPED (port 443 not reachable)"
    issues=$(echo "$issues" | jq '. + ["port_443_closed"]')
  fi

  overall="healthy"
  [ "$(echo "$issues" | jq 'length')" -gt 0 ] && overall="degraded"

  echo "   Overall   → $([ "$overall" = "healthy" ] && echo "✅ HEALTHY" || echo "🔴 DEGRADED")"

  record=$(jq -n \
    --arg  name         "$name"        \
    --arg  host         "$host"        \
    --arg  env          "$env"         \
    --arg  port80       "$port80"      \
    --arg  port443      "$port443"     \
    --arg  ssl_status   "$ssl_status"  \
    --arg  ssl_expiry   "$ssl_expiry"  \
    --arg  ssl_subject  "$ssl_subject" \
    --arg  ssl_issuer   "$ssl_issuer"  \
    --argjson ssl_days_left "${ssl_days_left:-null}" \
    --argjson issues    "$issues"      \
    --arg  overall      "$overall"     \
    '{name:$name, host:$host, env:$env,
      port_80:$port80, port_443:$port443,
      ssl_status:$ssl_status, ssl_expiry:$ssl_expiry,
      ssl_subject:$ssl_subject, ssl_issuer:$ssl_issuer,
      ssl_days_left:$ssl_days_left,
      issues:$issues, overall:$overall}')

  results=$(echo "$results" | jq ". + [$record]")

done < <(jq -c '.hosts[]' "$HOSTS_FILE")

# ── Write final JSON ──────────────────────────────────────────────────────────
final=$(jq -n \
  --arg  ts      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson checks "$results" \
  '{timestamp:$ts, checks:$checks}')

echo "$final" > "$OUTPUT_FILE"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

healthy=$(echo "$final" | jq '[.checks[] | select(.overall=="healthy")] | length')
degraded=$(echo "$final" | jq '[.checks[] | select(.overall=="degraded")] | length')
total=$(echo "$final"   | jq '.checks | length')

echo "  SUMMARY: $total hosts | ✅ $healthy healthy | 🔴 $degraded degraded"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

[ "$degraded" -gt 0 ] && exit 1 || exit 0
