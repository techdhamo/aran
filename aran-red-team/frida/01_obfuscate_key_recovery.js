/**
 * Aran Red-Team | Script 01: OBFUSCATE Key Recovery
 *
 * Objective:
 *   Attempt to recover the compile-time XOR key embedded in libaran-secure.so
 *   by hooking AranObfuscatedString::decrypt() and capturing the return pointer
 *   before it goes out of scope. Also attempts to brute-force the key by
 *   XOR-ing known plaintext (e.g. "/proc/self/maps") against captured ciphertext
 *   in the .rodata section.
 *
 * Expected result (hardened build):
 *   - The decrypted buffer is stack-allocated and zeroed on scope exit;
 *     hooking the return pointer only gives a live reference while the
 *     calling function is on the stack. No persistent plaintext in memory.
 *   - The rolling key (KEY ^ index) means brute-forcing a single byte does
 *     not reveal the full key — each position has a different effective key.
 *   - REPORT: "PASS" if no consistent key is recovered across 3+ needles.
 *
 * Usage:
 *   frida -U -f <pkg> -l 01_obfuscate_key_recovery.js --no-pause
 */

"use strict";

const REPORT = { id: "01_obfuscate_key_recovery", findings: [], verdict: "PASS" };

// ── Step 1: Find libaran-secure.so base ─────────────────────────────────────
const MODULE_NAME = "libaran-secure.so";

function getModuleBase() {
    const mod = Process.findModuleByName(MODULE_NAME);
    if (!mod) {
        REPORT.findings.push({ level: "INFO", msg: `${MODULE_NAME} not yet loaded` });
        return null;
    }
    REPORT.findings.push({ level: "INFO", msg: `${MODULE_NAME} base: ${mod.base}` });
    return mod;
}

// ── Step 2: Scan .rodata for candidate XOR-encrypted strings ────────────────
function scanRodata(mod) {
    // Known plaintext needle: first 4 bytes of "/pro" = 0x2F 0x70 0x72 0x6F
    const needle = [0x2F, 0x70, 0x72, 0x6F]; // "/pro"
    const rodata = mod.findExportByName(null); // heuristic: walk sections

    // Walk readable non-executable memory ranges within the module
    const ranges = Process.enumerateRangesSync({ protection: "r--" })
        .filter(r => r.base >= mod.base && r.base < mod.base.add(mod.size));

    const candidates = [];
    for (const range of ranges) {
        try {
            const bytes = range.base.readByteArray(range.size);
            if (!bytes) continue;
            const buf = new Uint8Array(bytes);

            for (let i = 0; i < buf.length - 4; i++) {
                // Try every possible key byte (1-255) against position 0
                for (let key = 1; key < 256; key++) {
                    // Rolling key: effective[j] = key ^ j
                    if (
                        (buf[i]   ^ (key ^ 0)) === needle[0] &&
                        (buf[i+1] ^ (key ^ 1)) === needle[1] &&
                        (buf[i+2] ^ (key ^ 2)) === needle[2] &&
                        (buf[i+3] ^ (key ^ 3)) === needle[3]
                    ) {
                        // Candidate found — try to decrypt up to 20 bytes
                        let decoded = "";
                        for (let j = 0; j < 20 && (i + j) < buf.length; j++) {
                            const c = buf[i + j] ^ (key ^ j);
                            if (c === 0) break;
                            decoded += String.fromCharCode(c);
                        }
                        candidates.push({ addr: range.base.add(i), key, decoded });
                    }
                }
            }
        } catch (_) {}
    }

    if (candidates.length > 0) {
        REPORT.verdict = "FAIL";
        candidates.forEach(c => {
            REPORT.findings.push({
                level: "CRITICAL",
                msg: `Encrypted needle at ${c.addr} decrypts with key=0x${c.key.toString(16).toUpperCase()} → "${c.decoded}"`
            });
        });
    } else {
        REPORT.findings.push({ level: "PASS", msg: "No plaintext needle recovered from .rodata scan" });
    }
}

// ── Step 3: Hook decrypt() return value via Interceptor ─────────────────────
function hookDecrypt(mod) {
    // Symbol may be mangled; search exports for anything containing "decrypt"
    const exports = mod.enumerateExports();
    const targets = exports.filter(e =>
        e.name.toLowerCase().includes("decrypt") ||
        e.name.toLowerCase().includes("obfuscate")
    );

    if (targets.length === 0) {
        REPORT.findings.push({ level: "INFO", msg: "No exported decrypt symbol (expected in stripped build)" });
        return;
    }

    targets.forEach(sym => {
        Interceptor.attach(ptr(sym.address), {
            onLeave(retval) {
                try {
                    const s = retval.readUtf8String();
                    REPORT.findings.push({
                        level: "CRITICAL",
                        msg: `decrypt() returned plaintext via hook: "${s}" at ${sym.name}`
                    });
                    REPORT.verdict = "FAIL";
                } catch (_) {
                    REPORT.findings.push({ level: "INFO", msg: `decrypt() return pointer not readable (stack-allocated, already freed)` });
                }
            }
        });
    });
}

// ── Main ─────────────────────────────────────────────────────────────────────
Java.perform(() => {
    const mod = getModuleBase();
    if (mod) {
        scanRodata(mod);
        hookDecrypt(mod);
    }

    setTimeout(() => {
        console.log(JSON.stringify(REPORT, null, 2));
    }, 5000);
});
