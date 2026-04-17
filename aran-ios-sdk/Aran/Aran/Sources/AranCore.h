// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

#ifndef AranCore_h
#define AranCore_h

#include <stdint.h>
#include <stdbool.h>

// Bitmask result for aran_scan_all()
#define ARAN_THREAT_NONE              0x00000
#define ARAN_THREAT_DEBUGGER          0x00001
#define ARAN_THREAT_DEBUGGER_MACH     0x00002
#define ARAN_THREAT_JAILBREAK_FS      0x00004
#define ARAN_THREAT_JAILBREAK_SYMLINK 0x00008
#define ARAN_THREAT_JAILBREAK_WRITE   0x00010
#define ARAN_THREAT_FRIDA_DYLD        0x00020
#define ARAN_THREAT_SUBSTRATE_DYLD    0x00040
#define ARAN_THREAT_FRIDA_PORT        0x00080
#define ARAN_THREAT_DYLD_ENVVAR       0x00100
#define ARAN_THREAT_FISHHOOK          0x00200
#define ARAN_THREAT_JAILBREAK_FORK    0x00400
#define ARAN_THREAT_TTY_ATTACHED      0x00800
#define ARAN_THREAT_PPID_SUSPICIOUS   0x01000
#define ARAN_THREAT_SANDBOX_VIOLATION 0x02000
#define ARAN_THREAT_SHADOW_CYDIA      0x04000

#ifdef __cplusplus
extern "C" {
#endif

// Scorched Earth: global compromise flag.
// When true, AranURLProtocol blackholes ALL network requests.
// Set by AranScorchedEarth.swift when a critical threat is detected.
extern volatile bool g_aran_is_compromised;

// Phase 2: Low-level C engine

/// Public sysctl API check for P_TRACED flag.
/// Returns true if a debugger is attached to the current process.
/// Uses only the public sysctl(3) POSIX API — no ptrace.
bool aran_check_debugger_sysctl(void);

/// Public task_get_exception_ports() check for Mach-level debuggers.
/// Uses <mach/task.h> — a public Mach header.
bool aran_check_mach_ports(void);

/// Sandbox integrity test: attempts fopen() write to a restricted path.
/// If successful, the iOS sandbox has been compromised (jailbreak).
/// Uses only public POSIX fopen(3).
bool aran_check_sandbox_violation(void);

/// Check isatty(STDOUT/STDERR) for debugger console attachment.
bool aran_check_tty_attached(void);

/// Check if parent PID is suspicious (not launchd pid 1).
bool aran_check_ppid_suspicious(void);

/// Parse loaded Mach-O images for Frida/Substrate/Substitute/etc dylibs.
/// Returns bitmask of ARAN_THREAT_FRIDA_DYLD | ARAN_THREAT_SUBSTRATE_DYLD.
uint32_t aran_check_dyld_injections(void);

/// Check DYLD_INSERT_LIBRARIES and other env vars for injection.
bool aran_check_dyld_environment(void);

/// Check Frida default ports (27042, 27043) via raw socket connect.
bool aran_check_frida_port(void);

/// Raw syscall/stat based jailbreak filesystem check.
/// Uses comprehensive proprietary heuristic paths for Jailbreak detection.
bool aran_check_jailbreak_fs(void);

/// Check for symbolic links on restricted system directories.
bool aran_check_jailbreak_symlinks(void);

/// Check if we can write to restricted paths.
bool aran_check_jailbreak_write(void);

/// Check for Shadow Cydia jailbreak bypass tool using multiple detection methods.
/// Shadow Cydia hooks filesystem operations to hide jailbreak traces.
bool aran_check_shadow_cydia(void);

/// Combined scan: returns bitmask of all ARAN_THREAT_* flags.
uint32_t aran_scan_all(void);

#ifdef __cplusplus
}
#endif

#endif /* AranCore_h */
