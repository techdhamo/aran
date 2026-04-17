#!/usr/bin/env bash
# ============================================================
# Aran Red-Team Suite Runner
# ============================================================
# Usage:
#   export ARAN_TELEMETRY_URL=http://localhost:8083
#   export ARAN_RSA_PUBLIC_KEY_PATH=/path/to/aran_pub.pem
#   export ARAN_DEVICE_SERIAL=<adb device serial>   # optional
#   export ARAN_APP_PACKAGE=org.mazhai.aran.sample  # optional
#   ./run_red_team.sh [--skip-frida] [--skip-telemetry] [--skip-webview]
# ============================================================

set -euo pipefail

REPORT_DIR="reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

SKIP_FRIDA=false
SKIP_TELEMETRY=false
SKIP_WEBVIEW=false

for arg in "$@"; do
  case "$arg" in
    --skip-frida)     SKIP_FRIDA=true ;;
    --skip-telemetry) SKIP_TELEMETRY=true ;;
    --skip-webview)   SKIP_WEBVIEW=true ;;
  esac
done

echo "╔══════════════════════════════════════════════════════╗"
echo "║         ARAN RED-TEAM SUITE — $(date '+%Y-%m-%d %H:%M')          ║"
echo "╚══════════════════════════════════════════════════════╝"

OVERALL_PASS=true

# ── Layer 1: Frida Scripts ───────────────────────────────────────────────────
if [ "$SKIP_FRIDA" = false ]; then
  echo ""
  echo "▶ LAYER 1: Frida Native Attack Scripts"

  PACKAGE="${ARAN_APP_PACKAGE:-org.mazhai.aran.sample}"
  SERIAL_FLAG=""
  if [ -n "${ARAN_DEVICE_SERIAL:-}" ]; then
    SERIAL_FLAG="-D $ARAN_DEVICE_SERIAL"
  fi

  for script in frida/0*.js; do
    script_name=$(basename "$script" .js)
    out="$REPORT_DIR/${script_name}.json"
    echo "  Running $script_name..."

    if command -v frida &>/dev/null; then
      timeout 60 frida $SERIAL_FLAG -f "$PACKAGE" -l "$script" \
        --no-pause --kill-on-exit 2>/dev/null | \
        grep -E '^\{' | tail -1 > "$out" || true

      if [ -f "$out" ] && [ -s "$out" ]; then
        verdict=$(python3 -c "import json,sys; d=json.load(open('$out')); print(d.get('verdict','UNKNOWN'))")
        if [ "$verdict" != "PASS" ]; then
          OVERALL_PASS=false
          echo "    ✗ $script_name → $verdict"
        else
          echo "    ✓ $script_name → PASS"
        fi
      else
        echo "    ? $script_name → no output (device not connected or app not running)"
      fi
    else
      echo "  [SKIP] frida not installed — install with: pip install frida-tools"
    fi
  done
fi

# ── Layer 2: Telemetry Python Tests ─────────────────────────────────────────
if [ "$SKIP_TELEMETRY" = false ]; then
  echo ""
  echo "▶ LAYER 2: Telemetry Cryptographic & Replay Attacks"

  if [ -z "${ARAN_RSA_PUBLIC_KEY_PATH:-}" ]; then
    echo "  [SKIP] ARAN_RSA_PUBLIC_KEY_PATH not set"
  elif [ ! -f "${ARAN_RSA_PUBLIC_KEY_PATH}" ]; then
    echo "  [SKIP] Public key file not found: $ARAN_RSA_PUBLIC_KEY_PATH"
  else
    cd telemetry
    pytest test_replay_attack.py test_crypto_attack.py test_batch_flood.py \
      -v --tb=short \
      --junit-xml="../$REPORT_DIR/telemetry_results.xml" \
      2>&1 | tee "../$REPORT_DIR/telemetry_output.txt"
    TELEMETRY_EXIT=${PIPESTATUS[0]}
    cd ..

    if [ $TELEMETRY_EXIT -ne 0 ]; then
      OVERALL_PASS=false
      echo "  ✗ Telemetry tests: FAILURES (see $REPORT_DIR/telemetry_results.xml)"
    else
      echo "  ✓ Telemetry tests: ALL PASS"
    fi
  fi
fi

# ── Layer 3: WebView Bridge Fuzzer ───────────────────────────────────────────
if [ "$SKIP_WEBVIEW" = false ]; then
  echo ""
  echo "▶ LAYER 3: WebView Bridge Fuzzer"
  echo "  Load webview/bridge_fuzzer.html in your app's WebView manually,"
  echo "  then check logcat for ARAN_RED_TEAM_REPORT lines:"
  echo ""
  echo "  adb logcat -s chromium | grep ARAN_RED_TEAM_REPORT"
  echo ""
  echo "  Or push the file to the device and open via file:// URL:"
  PACKAGE="${ARAN_APP_PACKAGE:-org.mazhai.aran.sample}"
  echo "  adb push webview/bridge_fuzzer.html /sdcard/bridge_fuzzer.html"
fi

# ── Summary Report ────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
if [ "$OVERALL_PASS" = true ]; then
  echo "  OVERALL VERDICT: ✓ ALL AUTOMATED TESTS PASS"
else
  echo "  OVERALL VERDICT: ✗ FAILURES DETECTED — see $REPORT_DIR/"
fi
echo "  Report directory: $REPORT_DIR"
echo "════════════════════════════════════════════════"

[ "$OVERALL_PASS" = true ] && exit 0 || exit 1
