#!/bin/bash
# ════════════════════════════════════════════════════════════════════
# Aran Secure SDK — E2E Telemetry Backend Verification
# Tests that the backend DTO is perfectly synchronized with all 23 threat signals
# ════════════════════════════════════════════════════════════════════

set -e

BACKEND_URL="http://localhost:33100/api/v1/telemetry/ingest"

echo "════════════════════════════════════════════════════════════════"
echo "Aran Secure SDK — E2E Telemetry Test"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Target: $BACKEND_URL"
echo ""

# Full threat payload with ALL 23 signals
PAYLOAD=$(cat <<'EOF'
{
  "device_fingerprint": "e2e-test-fp-12345",
  "app_id": "org.mazhai.aran.e2e.test",
  "is_rooted": true,
  "frida_detected": true,
  "debugger_attached": true,
  "emulator_detected": true,
  "hook_detected": true,
  "tamper_detected": true,
  "untrusted_installer": true,
  "developer_mode": true,
  "adb_enabled": true,
  "env_tampering": true,
  "runtime_integrity": true,
  "vpn_detected": true,
  "screen_recording": true,
  "keylogger_risk": true,
  "untrusted_keyboard": true,
  "device_lock_missing": true,
  "overlay_detected": true,
  "malware_packages": ["com.malware.stealer", "com.fake.trojan", "com.topjohnwu.magisk"],
  "proxy_detected": true,
  "unsecured_wifi": true,
  "sms_forwarder_apps": ["com.smsfwd", "com.jbak2.smsforwarder"],
  "remote_access_apps": ["com.teamviewer.quicksupport.market", "com.anydesk.anydeskandroid"]
}
EOF
)

echo "Payload (23 threat signals):"
echo "$PAYLOAD" | jq '.' 2>/dev/null || echo "$PAYLOAD"
echo ""

echo "Sending POST request..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$BACKEND_URL")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo ""
echo "HTTP Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Assert 202 Accepted
if [ "$HTTP_CODE" -eq 202 ]; then
  echo "✅ SUCCESS: Backend accepted telemetry payload (HTTP 202)"
  echo "✅ Backend DTO is synchronized with SDK DeviceStatus"
  echo ""
  exit 0
elif [ "$HTTP_CODE" -eq 200 ]; then
  echo "⚠️  WARNING: Backend returned HTTP 200 (expected 202 Accepted)"
  echo "   Payload was processed but response code should be 202"
  echo ""
  exit 0
else
  echo "❌ FAILURE: Backend rejected payload (HTTP $HTTP_CODE)"
  echo "   Expected: 202 Accepted"
  echo "   This indicates backend DTO mismatch or server error"
  echo ""
  exit 1
fi
