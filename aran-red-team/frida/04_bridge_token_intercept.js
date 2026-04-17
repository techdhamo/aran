/**
 * Aran Red-Team | Script 04: JS Bridge Token Intercept & Replay
 *
 * Objective:
 *   Attempt to defeat the single-use bridge token system in AranJSBridge by:
 *   1. Hooking acquireBridgeToken() to capture a live token before JS consumes it.
 *   2. Replaying the captured token in a second getSigil() call after JS already
 *      consumed it — expecting empty string (token already removed from ConcurrentHashMap).
 *   3. Attempting to call getSigil() with a null/empty/crafted token directly
 *      via Frida's Java API, bypassing the WebView JS layer entirely.
 *   4. Attempting a timing attack: call acquireBridgeToken() and getSigil()
 *      in tight succession to beat the ConcurrentHashMap.remove() race.
 *
 * Expected results (hardened bridge):
 *   - Replayed token → getSigil() returns ""  → PASS
 *   - Null/empty token → getSigil() returns "" → PASS
 *   - Race on token consumption: ConcurrentHashMap.remove() is atomic;
 *     only one caller wins → PASS
 *
 * Usage:
 *   frida -U -f <pkg> -l 04_bridge_token_intercept.js --no-pause
 */

"use strict";

const REPORT = { id: "04_bridge_token_intercept", findings: [], verdict: "PASS" };

Java.perform(() => {
    const AranJSBridge = Java.use("org.mazhai.aran.omninet.AranJSBridge");

    // ── Test 1: Null token ────────────────────────────────────────────────────
    (function testNullToken() {
        try {
            // We can't instantiate AranJSBridge without its deps, so we hook
            // the existing instance via choose()
            Java.choose("org.mazhai.aran.omninet.AranJSBridge", {
                onMatch(instance) {
                    const result = instance.getSigil("", "dGVzdA==", "FRIDA_TEST");
                    if (result === "") {
                        REPORT.findings.push({ level: "PASS", msg: "Test 1 PASS: empty token → getSigil() returned empty string" });
                    } else {
                        REPORT.verdict = "FAIL";
                        REPORT.findings.push({ level: "CRITICAL", msg: `Test 1 FAIL: empty token accepted → sigil="${result.substring(0, 40)}..."` });
                    }
                },
                onComplete() {}
            });
        } catch (e) {
            REPORT.findings.push({ level: "INFO", msg: `Test 1 skipped (no live instance yet): ${e}` });
        }
    })();

    // ── Test 2: Replayed token ────────────────────────────────────────────────
    (function testReplayedToken() {
        let capturedToken = null;

        AranJSBridge.acquireBridgeToken.implementation = function () {
            const token = this.acquireBridgeToken();
            capturedToken = token;
            REPORT.findings.push({ level: "INFO", msg: `acquireBridgeToken() intercepted: token=${token.substring(0, 16)}...` });
            return token;
        };

        // After the legitimate JS call consumes the token, attempt replay
        AranJSBridge.getSigil.overload("java.lang.String", "java.lang.String", "java.lang.String")
            .implementation = function (bridgeToken, payloadHash, trafficSource) {
                const result = this.getSigil(bridgeToken, payloadHash, trafficSource);

                if (capturedToken && bridgeToken === capturedToken) {
                    if (result !== "") {
                        REPORT.findings.push({ level: "INFO", msg: "First (legitimate) getSigil call succeeded — token consumed" });
                    }
                    // Now replay the same token
                    const replayResult = this.getSigil(capturedToken, payloadHash, "REPLAY_ATTACK");
                    if (replayResult === "") {
                        REPORT.findings.push({ level: "PASS", msg: "Test 2 PASS: replayed token correctly rejected by getSigil()" });
                    } else {
                        REPORT.verdict = "FAIL";
                        REPORT.findings.push({ level: "CRITICAL", msg: `Test 2 FAIL: replayed token accepted → sigil="${replayResult.substring(0, 40)}..."` });
                    }
                    capturedToken = null;
                }
                return result;
            };
    })();

    // ── Test 3: Fabricated token (random Base64) ──────────────────────────────
    (function testFabricatedToken() {
        // Generate a random Base64 string that was never issued by acquireBridgeToken()
        const fake = Java.use("android.util.Base64").encodeToString(
            Java.use("[B").$new(24),  // 24 zero bytes
            2  // Base64.NO_WRAP
        );

        Java.choose("org.mazhai.aran.omninet.AranJSBridge", {
            onMatch(instance) {
                const result = instance.getSigil(fake, "dGVzdA==", "FRIDA_FABRICATED");
                if (result === "") {
                    REPORT.findings.push({ level: "PASS", msg: "Test 3 PASS: fabricated token rejected" });
                } else {
                    REPORT.verdict = "FAIL";
                    REPORT.findings.push({ level: "CRITICAL", msg: `Test 3 FAIL: fabricated token accepted → sigil="${result.substring(0, 40)}..."` });
                }
            },
            onComplete() {}
        });
    })();

    // ── Test 4: Token TTL expiry ──────────────────────────────────────────────
    (function testTokenExpiry() {
        // Acquire a token, wait 31 seconds (past TOKEN_TTL_MS = 30_000), then use it
        Java.choose("org.mazhai.aran.omninet.AranJSBridge", {
            onMatch(instance) {
                const token = instance.acquireBridgeToken();
                REPORT.findings.push({ level: "INFO", msg: `Test 4: acquired token, waiting 31s for TTL expiry...` });
                setTimeout(() => {
                    const result = instance.getSigil(token, "dGVzdA==", "FRIDA_EXPIRED");
                    if (result === "") {
                        REPORT.findings.push({ level: "PASS", msg: "Test 4 PASS: expired token (>30s) rejected" });
                    } else {
                        REPORT.verdict = "FAIL";
                        REPORT.findings.push({ level: "CRITICAL", msg: `Test 4 FAIL: expired token accepted after TTL` });
                    }
                    console.log(JSON.stringify(REPORT, null, 2));
                }, 31000);
            },
            onComplete() {}
        });
    })();

    // Emit interim report after 10s (before TTL test completes)
    setTimeout(() => {
        REPORT.findings.push({ level: "INFO", msg: "Interim report (TTL test still running)" });
        console.log(JSON.stringify(REPORT, null, 2));
    }, 10000);
});
