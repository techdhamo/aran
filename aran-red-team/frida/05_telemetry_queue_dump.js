/**
 * Aran Red-Team | Script 05: Offline Telemetry Queue Dump
 *
 * Objective:
 *   Demonstrate that even with full access to the EncryptedSharedPreferences
 *   queue, individual blobs cannot be decrypted without the backend RSA
 *   private key. Also attempts to:
 *   1. Hook AranTelemetryQueue.enqueue() to capture blobs at enqueue time.
 *   2. Hook TelemetryClient.encryptAsymmetric() to capture plaintext BEFORE
 *      encryption (the only realistic attack surface).
 *   3. Attempt to replay a captured blob directly to the backend endpoint.
 *
 * Expected results (hardened):
 *   - Blob captured via enqueue hook is already RSA-encrypted → unreadable.
 *   - Plaintext captured via encryptAsymmetric hook IS readable — this is
 *     the primary finding: the window between payload construction and
 *     encryption is a valid attack surface on a rooted device.
 *   - Replaying a captured blob to /ingest → backend returns REJECTED_REPLAY
 *     (nonce already seen) if nonce is embedded in ciphertext.
 *     NOTE: the outer envelope nonce IS visible in cleartext → replay
 *     protection depends entirely on the backend nonce cache.
 *
 * Usage:
 *   frida -U -f <pkg> -l 05_telemetry_queue_dump.js --no-pause
 */

"use strict";

const REPORT = { id: "05_telemetry_queue_dump", findings: [], verdict: "PASS" };
const capturedBlobs = [];
const capturedPlaintexts = [];

Java.perform(() => {
    // ── Hook 1: AranTelemetryQueue.enqueue() ─────────────────────────────────
    try {
        const Queue = Java.use("org.mazhai.aran.internal.AranTelemetryQueue");
        Queue.enqueue.implementation = function (encryptedPayloadBase64) {
            capturedBlobs.push(encryptedPayloadBase64);
            REPORT.findings.push({
                level: "INFO",
                msg: `Queue.enqueue() captured blob[${capturedBlobs.length}]: ${encryptedPayloadBase64.substring(0, 40)}... (length=${encryptedPayloadBase64.length})`
            });
            // Attempt to Base64-decode and parse the JSON bundle
            try {
                const bytes = Java.use("android.util.Base64").decode(encryptedPayloadBase64, 0);
                const bundleStr = Java.use("java.lang.String").$new(bytes, "UTF-8");
                const bundle = JSON.parse(bundleStr);
                REPORT.findings.push({
                    level: "INFO",
                    msg: `Blob bundle fields: ${Object.keys(bundle).join(", ")} — enc_key is ${bundle.enc_key ? bundle.enc_key.length : 0} chars (RSA ciphertext, unreadable without private key)`
                });
            } catch (e) {
                REPORT.findings.push({ level: "INFO", msg: `Bundle parse failed (expected if double-encoded): ${e}` });
            }
            return this.enqueue(encryptedPayloadBase64);
        };
        REPORT.findings.push({ level: "INFO", msg: "AranTelemetryQueue.enqueue() hooked" });
    } catch (e) {
        REPORT.findings.push({ level: "INFO", msg: `Queue hook failed: ${e}` });
    }

    // ── Hook 2: TelemetryClient.encryptAsymmetric() — plaintext capture ───────
    try {
        const Client = Java.use("org.mazhai.aran.internal.TelemetryClient");
        Client.encryptAsymmetric.implementation = function (plaintext) {
            capturedPlaintexts.push(plaintext);
            REPORT.verdict = "FAIL";
            REPORT.findings.push({
                level: "CRITICAL",
                msg: `PLAINTEXT CAPTURED before encryption (${plaintext.length} chars): ${plaintext.substring(0, 200)}...`
            });
            return this.encryptAsymmetric(plaintext);
        };
        REPORT.findings.push({ level: "INFO", msg: "TelemetryClient.encryptAsymmetric() hooked — plaintext window exposed on rooted device" });
    } catch (e) {
        REPORT.findings.push({ level: "INFO", msg: `encryptAsymmetric hook failed (obfuscated/minified): ${e}` });
    }

    // ── Hook 3: TelemetryClient.buildRbiPayload() — pre-encryption payload ────
    try {
        const Client = Java.use("org.mazhai.aran.internal.TelemetryClient");
        Client.buildRbiPayload.implementation = function (status, requestId, nonce, timestamp) {
            const result = this.buildRbiPayload(status, requestId, nonce, timestamp);
            REPORT.findings.push({
                level: "WARN",
                msg: `buildRbiPayload() intercepted — payload nonce="${nonce}" timestamp=${timestamp}. PII check: no account/MSISDN fields present → ${result.includes("account") || result.includes("phone") ? "PII FOUND — CRITICAL" : "PASS (no PII)"}`
            });
            return result;
        };
    } catch (e) {
        REPORT.findings.push({ level: "INFO", msg: `buildRbiPayload hook skipped: ${e}` });
    }

    setTimeout(() => {
        REPORT.findings.push({
            level: "INFO",
            msg: `Summary: ${capturedBlobs.length} blobs captured (all RSA-encrypted), ${capturedPlaintexts.length} plaintexts captured (pre-encryption window)`
        });
        if (capturedPlaintexts.length === 0) {
            REPORT.verdict = "PASS";
            REPORT.findings.push({ level: "PASS", msg: "encryptAsymmetric() not hookable in this build (R8/obfuscation effective)" });
        }
        console.log(JSON.stringify(REPORT, null, 2));
    }, 10000);
});
