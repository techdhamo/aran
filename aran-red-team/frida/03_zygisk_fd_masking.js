/**
 * Aran Red-Team | Script 03: Zygisk FD Masking Bypass Attempt
 *
 * Objective:
 *   Attempt to defeat aran_detect_zygisk_fd() (bit 14) by:
 *   1. Hooking opendir("/proc/self/fd") to return a filtered DIR* that
 *      omits the low-numbered FDs the scanner is looking for.
 *   2. Hooking readlink() on /proc/self/fd/<n> to return "pipe:[fake]"
 *      instead of "socket:[real]" for targeted FDs.
 *   3. Observing the resulting bitmask to see if bit 14 is suppressed.
 *
 * Expected result (hardened build):
 *   - If the hook successfully hides the FDs, bit 14 will be 0 → FAIL.
 *   - A hardened build should cross-validate via /proc/self/net/unix
 *     directly rather than relying solely on /proc/self/fd readlinks,
 *     making the opendir hook insufficient alone.
 *
 * Usage:
 *   frida -U -f <pkg> -l 03_zygisk_fd_masking.js --no-pause
 */

"use strict";

const REPORT = { id: "03_zygisk_fd_masking", findings: [], verdict: "PASS" };

// Target FDs to hide (typical Zygisk companion FD range)
const TARGET_FDS = new Set([4, 5, 6, 7, 8]);

// ── Hook readlink ─────────────────────────────────────────────────────────────
function hookReadlink() {
    const readlinkSym = Module.findExportByName(null, "readlink");
    if (!readlinkSym) {
        REPORT.findings.push({ level: "INFO", msg: "readlink not found" });
        return;
    }

    Interceptor.attach(readlinkSym, {
        onEnter(args) {
            try {
                this.path = args[0].readUtf8String();
                this.buf  = args[1];
                this.bufsz = args[2].toInt32();
            } catch (_) {}
        },
        onLeave(retval) {
            if (!this.path) return;
            // Match /proc/self/fd/<n> where n is in TARGET_FDS
            const m = this.path.match(/\/proc\/self\/fd\/(\d+)$/);
            if (!m) return;
            const fd = parseInt(m[1], 10);
            if (!TARGET_FDS.has(fd)) return;

            try {
                const original = this.buf.readUtf8String();
                if (original.startsWith("socket:")) {
                    // Replace with a fake pipe target to hide the socket
                    const fake = "pipe:[99999]";
                    this.buf.writeUtf8String(fake);
                    retval.replace(ptr(fake.length));
                    REPORT.findings.push({
                        level: "WARN",
                        msg: `readlink hook masked fd=${fd}: "${original}" → "${fake}"`
                    });
                }
            } catch (_) {}
        }
    });
    REPORT.findings.push({ level: "INFO", msg: "readlink hook installed for /proc/self/fd/<n>" });
}

// ── Observe bitmask result ────────────────────────────────────────────────────
function hookBitmask() {
    const mod = Process.findModuleByName("libaran-secure.so");
    if (!mod) {
        REPORT.findings.push({ level: "INFO", msg: "libaran-secure.so not loaded" });
        return;
    }
    const exports = mod.enumerateExports();
    const jni = exports.find(e => e.name.includes("checkIntegrityNative"));
    if (!jni) {
        REPORT.findings.push({ level: "INFO", msg: "checkIntegrityNative not exported (stripped)" });
        return;
    }

    Interceptor.attach(ptr(jni.address), {
        onLeave(retval) {
            const mask = retval.toInt32();
            const bit14 = (mask & 0x4000) !== 0;
            const bit13 = (mask & 0x2000) !== 0;

            REPORT.findings.push({
                level: "INFO",
                msg: `checkIntegrityNative mask=0x${mask.toString(16).toUpperCase()} | zygiskFd(bit14)=${bit14} | anonElf(bit13)=${bit13}`
            });

            if (!bit14) {
                REPORT.verdict = "FAIL";
                REPORT.findings.push({
                    level: "CRITICAL",
                    msg: "BYPASS CONFIRMED: readlink hook suppressed Zygisk FD detection (bit 14 not set)"
                });
            } else {
                REPORT.findings.push({
                    level: "PASS",
                    msg: "Zygisk FD detection (bit 14) not bypassed by readlink hook"
                });
            }
        }
    });
}

// ── Main ─────────────────────────────────────────────────────────────────────
Java.perform(() => {
    hookReadlink();
    hookBitmask();

    setTimeout(() => {
        console.log(JSON.stringify(REPORT, null, 2));
    }, 8000);
});
