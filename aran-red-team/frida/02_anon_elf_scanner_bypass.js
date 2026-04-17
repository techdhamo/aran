/**
 * Aran Red-Team | Script 02: Anonymous ELF Scanner Bypass Attempt
 *
 * Objective:
 *   Attempt to defeat aran_scan_anon_elf() (bit 13) by:
 *   1. Hooking pread() to return a zeroed buffer when the fd points to
 *      /proc/self/mem and the offset falls within an anon r-xp region.
 *   2. Allocating an anonymous r-xp region with an ELF header ourselves,
 *      then verifying the scanner catches it BEFORE the hook fires.
 *   3. Patching the ELF magic in our test region after scanner invocation
 *      to confirm the hook would have prevented detection.
 *
 * Expected result (hardened build):
 *   - The scanner is called from checkIntegrityNative() before the app
 *     has a chance to install JS hooks. A Frida hook installed AFTER
 *     process start may arrive too late for the first scan cycle.
 *   - pread() interception: if the hook succeeds in zeroing the read,
 *     the scanner returns a false negative → FAIL (bypass confirmed).
 *   - REPORT: "PASS" if scanner correctly flags the planted ELF region
 *     even with the pread hook active.
 *
 * Usage:
 *   frida -U -f <pkg> -l 02_anon_elf_scanner_bypass.js --no-pause
 */

"use strict";

const REPORT = { id: "02_anon_elf_scanner_bypass", findings: [], verdict: "PASS" };

// ── Step 1: Plant a test anonymous ELF region ────────────────────────────────
let plantedRegion = null;

function plantAnonElf() {
    // Allocate 4KB anonymous executable memory and write ELF magic
    const mem = Memory.alloc(4096);
    Memory.protect(mem, 4096, "r-x");
    try {
        // Write ELF magic: 0x7F 'E' 'L' 'F'
        mem.writeByteArray([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
        plantedRegion = mem;
        REPORT.findings.push({
            level: "INFO",
            msg: `Planted anon ELF region at ${mem} (4096 bytes, r-x)`
        });
    } catch (e) {
        REPORT.findings.push({ level: "INFO", msg: `Could not write to r-x region (expected): ${e}` });
    }
}

// ── Step 2: Hook pread to intercept /proc/self/mem reads ─────────────────────
let preadHookActive = false;
let preadInterceptions = 0;

function hookPread() {
    const preadSym = Module.findExportByName(null, "pread64") ||
                     Module.findExportByName(null, "pread");
    if (!preadSym) {
        REPORT.findings.push({ level: "INFO", msg: "pread symbol not found" });
        return;
    }

    Interceptor.attach(preadSym, {
        onEnter(args) {
            this.fd   = args[0].toInt32();
            this.buf  = args[1];
            this.size = args[2].toInt32();
            this.off  = args[3];
        },
        onLeave(retval) {
            if (retval.toInt32() <= 0) return;
            try {
                const first = this.buf.readU8();
                // 0x7F = start of ELF magic
                if (first === 0x7F && this.size >= 4) {
                    const magic = this.buf.readByteArray(4);
                    const arr = new Uint8Array(magic);
                    if (arr[1] === 0x45 && arr[2] === 0x4C && arr[3] === 0x46) {
                        // Zero out the ELF magic to simulate bypass
                        this.buf.writeByteArray([0x00, 0x00, 0x00, 0x00]);
                        preadInterceptions++;
                        REPORT.findings.push({
                            level: "WARN",
                            msg: `pread hook zeroed ELF magic at fd=${this.fd} offset=${this.off} (interception #${preadInterceptions})`
                        });
                        preadHookActive = true;
                    }
                }
            } catch (_) {}
        }
    });
    REPORT.findings.push({ level: "INFO", msg: "pread hook installed" });
}

// ── Step 3: Hook aran_scan_anon_elf to observe return value ──────────────────
function hookScanAnonElf() {
    const mod = Process.findModuleByName("libaran-secure.so");
    if (!mod) {
        REPORT.findings.push({ level: "INFO", msg: "libaran-secure.so not loaded yet" });
        return;
    }

    // Symbol is internal (not exported). Search by scanning for the function
    // pattern. We observe the return value of checkIntegrityNative instead.
    const exports = mod.enumerateExports();
    const jniBridge = exports.find(e =>
        e.name.includes("checkIntegrityNative") || e.name.includes("AranNative")
    );

    if (!jniBridge) {
        REPORT.findings.push({ level: "INFO", msg: "checkIntegrityNative not exported (stripped — expected)" });
        return;
    }

    Interceptor.attach(ptr(jniBridge.address), {
        onLeave(retval) {
            const mask = retval.toInt32();
            const bit13 = (mask & 0x2000) !== 0;
            const bit14 = (mask & 0x4000) !== 0;

            REPORT.findings.push({
                level: bit13 ? "INFO" : (preadHookActive ? "FAIL" : "INFO"),
                msg: `checkIntegrityNative returned mask=0x${mask.toString(16).toUpperCase()} | anonElf=${bit13} | zygiskFd=${bit14}`
            });

            if (preadHookActive && !bit13) {
                REPORT.verdict = "FAIL";
                REPORT.findings.push({
                    level: "CRITICAL",
                    msg: `BYPASS CONFIRMED: pread hook suppressed anon ELF detection (bit 13 not set)`
                });
            } else if (bit13) {
                REPORT.findings.push({
                    level: "PASS",
                    msg: `Scanner correctly detected anon ELF region despite hook attempt`
                });
            }
        }
    });
}

// ── Main ─────────────────────────────────────────────────────────────────────
Java.perform(() => {
    plantAnonElf();
    hookPread();
    hookScanAnonElf();

    setTimeout(() => {
        console.log(JSON.stringify(REPORT, null, 2));
    }, 8000);
});
