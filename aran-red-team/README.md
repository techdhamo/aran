# Aran Red-Team Suite

Automated attack harness for validating the Aran RASP SDK security properties.

## Structure

```
aran-red-team/
├── frida/
│   ├── 01_obfuscate_key_recovery.js     # XOR key brute-force + decrypt() hook
│   ├── 02_anon_elf_scanner_bypass.js    # pread() hook to suppress bit 13
│   ├── 03_zygisk_fd_masking.js          # readlink() hook to suppress bit 14
│   ├── 04_bridge_token_intercept.js     # token replay, null, fabricated, TTL
│   └── 05_telemetry_queue_dump.js       # plaintext capture pre-encryption
├── telemetry/
│   ├── conftest.py                      # shared crypto fixtures
│   ├── test_replay_attack.py            # T1-T4: nonce/timestamp replay
│   ├── test_crypto_attack.py            # C1-C6: wrong key, GCM tag, SHA-256
│   └── test_batch_flood.py              # B1-B4: oversized batch, concurrent flood
├── webview/
│   └── bridge_fuzzer.html               # W1-W8: JS-side token fuzzing
├── run_red_team.sh                      # orchestrator with CI exit codes
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt

# Set environment variables
export ARAN_TELEMETRY_URL=http://localhost:8083
export ARAN_RSA_PUBLIC_KEY_PATH=/path/to/aran_pub.pem
export ARAN_APP_PACKAGE=org.mazhai.aran.sample
export ARAN_DEVICE_SERIAL=<adb serial>      # optional

chmod +x run_red_team.sh
```

## Running

```bash
# Full suite
./run_red_team.sh

# Skip Frida (no device connected)
./run_red_team.sh --skip-frida

# Telemetry tests only
./run_red_team.sh --skip-frida --skip-webview

# WebView fuzzer only (manual step)
./run_red_team.sh --skip-frida --skip-telemetry
```

## Frida Scripts (individual)

```bash
frida -U -f org.mazhai.aran.sample -l frida/01_obfuscate_key_recovery.js --no-pause
frida -U -f org.mazhai.aran.sample -l frida/02_anon_elf_scanner_bypass.js --no-pause
frida -U -f org.mazhai.aran.sample -l frida/03_zygisk_fd_masking.js --no-pause
frida -U -f org.mazhai.aran.sample -l frida/04_bridge_token_intercept.js --no-pause
frida -U -f org.mazhai.aran.sample -l frida/05_telemetry_queue_dump.js --no-pause
```

## Expected Verdicts (hardened build)

| Script / Test | Expected | Confirms |
|---|---|---|
| 01 obfuscate_key_recovery | PASS | Rolling XOR defeats .rodata scan; stack buffer defeats hook |
| 02 anon_elf_scanner_bypass | PASS | pread() hook arrives after first scan cycle |
| 03 zygisk_fd_masking | PASS | /proc/self/net/unix cross-validation catches readlink mask |
| 04 bridge_token_intercept | PASS | ConcurrentHashMap.remove() is atomic; TTL enforced |
| 05 telemetry_queue_dump | PASS (R8 build) | encryptAsymmetric() not hookable when R8-minified |
| T1 nonce_replay | PASS | Backend LRU nonce cache rejects second submission |
| T2 stale_timestamp | PASS | 5-min clock skew window enforced |
| T3 future_timestamp | PASS | Future timestamps also rejected |
| C1 wrong_rsa_key | PASS | RSA-OAEP decryption fails without private key |
| C6 gcm_tag_corruption | PASS | AEAD authentication failure on corrupted tag |
| B4 concurrent_flood | PASS | Virtual thread executor handles 50 concurrent POSTs |
| W3 replayed_token | PASS | consumeToken() single-use via ConcurrentHashMap |
| W7 token_race | PASS | All 100 tokens consumed exactly once |

## Known Limitations

- **Script 02 / pread hook**: if Frida attaches after the first `checkIntegrityNative()`
  call (which happens at SDK init), bit 13 was already set before the hook fires.
  This is intentional — the scanner runs at startup before the JS environment exists.
- **Script 05 / R8 builds**: `encryptAsymmetric` is an internal Kotlin method.
  With R8 full-mode + obfuscation, it will be renamed and the hook will fail gracefully.
  This is the correct production configuration.
- **Test C3 sha256_mismatch**: only triggered if the backend has `payload_sha256`
  validation enabled (non-blank value in the envelope).
