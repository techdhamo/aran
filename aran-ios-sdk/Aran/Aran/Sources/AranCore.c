// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

#include "AranCore.h"

// Scorched Earth compromise flag — volatile prevents dead-store elimination.
// When true, AranURLProtocol returns NSURLErrorSecureConnectionFailed for ALL requests.
volatile bool g_aran_is_compromised = false;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/mach_init.h>

// ============================================================================
// MARK: - Debugger Detection (App Store Safe)
// ============================================================================

// Public sysctl(3) API — P_TRACED flag check.
// NO ptrace, NO inline assembly, NO dlsym("ptrace").
static bool _aran_sysctl_debugger_check(void) {
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));

    int mib[4];
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    size_t size = sizeof(info);
    int ret = sysctl(mib, 4, &info, &size, NULL, 0);
    if (ret != 0) {
        return false;
    }

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

bool aran_check_debugger_sysctl(void) {
    return _aran_sysctl_debugger_check();
}

// ============================================================================
// MARK: - Mach Exception Port Check (Phase 2)
// ============================================================================

bool aran_check_mach_ports(void) {
    mach_msg_type_number_t count = 0;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];

    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        EXC_MASK_ALL,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );

    if (kr != KERN_SUCCESS) {
        return false;
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (MACH_PORT_VALID(ports[i])) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// MARK: - TTY / PPID Checks
// ============================================================================

bool aran_check_tty_attached(void) {
    // isatty on stdout/stderr indicates terminal/debugger console
    if (isatty(STDOUT_FILENO) || isatty(STDERR_FILENO)) {
        return true;
    }
    return false;
}

bool aran_check_ppid_suspicious(void) {
    pid_t ppid = getppid();
    // On a non-debugged device, parent should be launchd (pid 1)
    // or SpringBoard. Debugger parents have different pids.
    return (ppid != 1);
}

// ============================================================================
// MARK: - DYLD Injection Detection (Phase 2)
// ============================================================================

// Suspicious dylib signatures for Frida detection
static const char *_aran_frida_signatures[] = {
    "FridaGadget",
    "frida-agent",
    "frida-gadget",
    "frida-core",
    "frida_agent",
    "libfrida",
    NULL
};

static const char *_aran_hooking_signatures[] = {
    "MobileSubstrate",
    "CydiaSubstrate",
    "SubstrateLoader",
    "SubstrateInserter",
    "SubstrateBootstrap",
    "Substitute",
    "substitute",
    "libsubstitute",
    "libhooker",
    "TweakInject",
    "libcycript",
    "cycript",
    "SSLKillSwitch",
    "SSLKillSwitch2",
    "Flex",
    "FLEXing",
    "Liberty",
    "LibertyLite",
    "A-Bypass",
    "FlyJB",
    "Shadow",
    "ShadowService",
    "Shadow.dylib",
    "shadowcydia",
    "Cephei",
    "ABDYLD",
    "ABSubLoader",
    "AppSyncUnified",
    "usr/lib/substrate",
    "usr/lib/TweakInject",
    "usr/lib/libhooker",
    NULL
};

uint32_t aran_check_dyld_injections(void) {
    uint32_t result = 0;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        // Check Frida signatures
        for (int j = 0; _aran_frida_signatures[j] != NULL; j++) {
            if (strstr(name, _aran_frida_signatures[j]) != NULL) {
                result |= ARAN_THREAT_FRIDA_DYLD;
                break;
            }
        }

        // Check hooking/substrate signatures
        for (int j = 0; _aran_hooking_signatures[j] != NULL; j++) {
            if (strstr(name, _aran_hooking_signatures[j]) != NULL) {
                result |= ARAN_THREAT_SUBSTRATE_DYLD;
                break;
            }
        }
    }

    // Also check via dlopen RTLD_NOLOAD (won't load, just checks if already loaded)
    const char *frida_libs[] = {"FridaGadget", "frida-agent", NULL};
    for (int i = 0; frida_libs[i] != NULL; i++) {
        void *h = dlopen(frida_libs[i], RTLD_NOLOAD);
        if (h) {
            dlclose(h);
            result |= ARAN_THREAT_FRIDA_DYLD;
        }
    }

    return result;
}

bool aran_check_dyld_environment(void) {
    // Check DYLD_INSERT_LIBRARIES environment variable
    const char *env_vars[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "_MSSafeMode",
        NULL
    };

    for (int i = 0; env_vars[i] != NULL; i++) {
        const char *val = getenv(env_vars[i]);
        // VAPT #14: Use strnlen instead of strlen to bound string length check
        if (val && strnlen(val, 4096) > 0) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// MARK: - Frida Port Check
// ============================================================================

bool aran_check_frida_port(void) {
    int ports[] = {27042, 27043};

    for (int i = 0; i < 2; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);

        if (ret == 0) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// MARK: - Jailbreak Filesystem Check (Phase 2)
// ============================================================================

// Comprehensive jailbreak paths for filesystem detection
static const char *_aran_jailbreak_paths[] = {
    // Core jailbreak apps
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Applications/Filza.app",
    "/Applications/iFile.app",
    "/Applications/NewTerm.app",
    // Substrate/hooking
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/usr/lib/ABDYLD.dylib",
    "/usr/lib/ABSubLoader.dylib",
    "/usr/lib/TweakInject",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    // Package managers
    "/private/var/lib/apt",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia",
    "/private/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/private/var/lib/dpkg/status",
    "/etc/apt",
    "/etc/apt/sources.list.d/electra.list",
    "/etc/apt/sources.list.d/sileo.sources",
    "/etc/apt/undecimus/undecimus.list",
    // Binaries
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/sshd",
    "/usr/bin/ssh",
    "/usr/bin/cycript",
    "/usr/sbin/sshd",
    "/usr/sbin/frida-server",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/cydia/firmware.sh",
    "/usr/local/bin/cycript",
    // Log/config files
    "/private/var/tmp/cydia.log",
    "/var/tmp/cydia.log",
    "/private/var/log/syslog",
    "/var/log/apt",
    "/var/cache/clutch.plist",
    "/var/cache/clutch_cracked.plist",
    "/var/lib/clutch/overdrive.dylib",
    "/etc/clutch.conf",
    "/etc/clutch_cracked.plist",
    // Jailbreak-specific artifacts
    "/private/var/stash",
    "/private/var/cache/apt/",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/Users/",
    "/private/jailbreak.txt",
    "/private/JailbreakTest.txt",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    // checkra1n / unc0ver / taurine / electra specific
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/var/binpack/Applications/loader.app",
    "/var/lib/undecimus/apt",
    "/jb/amfid_payload.dylib",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/jb/lzma",
    "/jb/offsets.plist",
    // palera1n jailbreak
    "/cores/binpack/.installed_palera1n",
    "/var/jb/.installed_palera1n",
    "/var/jb/basebin",
    "/var/jb/basebin/jbctl",
    "/var/jb/basebin/jbinit",
    "/var/jb/basebin/launchdhook.dylib",
    "/var/jb/usr/bin/apt",
    "/var/jb/usr/bin/dpkg",
    "/var/jb/Library/dpkg",
    // Dopamine jailbreak
    "/var/jb/Applications/Sileo.app",
    "/var/jb/usr/lib/libhooker.dylib",
    "/var/jb/usr/lib/libsubstitute.dylib",
    "/var/jb/usr/lib/TweakInject",
    "/var/jb/basebin/dopamine",
    // Serotonin jailbreak
    "/var/mobile/Library/Serotonin",
    "/var/mobile/Library/Serotonin/bootstrap",
    // Roothide / KFD-based jailbreaks
    "/var/containers/Bundle/.jbroot",
    "/private/preboot/jb",
    // Shadow Cydia specific
    "/var/mobile/Library/Preferences/com.shadow.shadowcydia.plist",
    "/var/mobile/Library/ShadowCydia",
    "/Library/MobileSubstrate/DynamicLibraries/Shadow.plist",
    "/usr/lib/libshadow.dylib",
    "/usr/libexec/shadow-service",
    "/private/var/tmp/shadow.log",
    // Cracked app indicators
    "/var/root/Documents/Cracked/",
    "/var/mobile/Library/Preferences/ABPattern",
    "/usr/share/jailbreak/injectme.plist",
    // SSH
    "/etc/ssh/sshd_config",
    // System integrity check paths
    "/System/Library/CoreServices/SystemVersion.plist",
    "/dev/tty",
    // Configuration profiles (sideloading)
    "/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles",
    NULL
};

bool aran_check_jailbreak_fs(void) {
    struct stat s;

    for (int i = 0; _aran_jailbreak_paths[i] != NULL; i++) {
        // Use stat() instead of NSFileManager (raw C, harder to hook)
        if (stat(_aran_jailbreak_paths[i], &s) == 0) {
            // Skip SystemVersion.plist and /dev/tty which exist on non-jailbroken
            if (strcmp(_aran_jailbreak_paths[i], "/System/Library/CoreServices/SystemVersion.plist") == 0 ||
                strcmp(_aran_jailbreak_paths[i], "/dev/tty") == 0) {
                continue;
            }
            return true;
        }
    }

    // Also try access() as a secondary check
    const char *critical_paths[] = {
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/frida-server",
        "/bin/bash",
        "/usr/bin/sshd",
        NULL
    };

    for (int i = 0; critical_paths[i] != NULL; i++) {
        if (access(critical_paths[i], F_OK) == 0) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// MARK: - Symbolic Link Check
// ============================================================================

bool aran_check_jailbreak_symlinks(void) {
    const char *symlink_paths[] = {
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/arm-apple-darwin9",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
        NULL
    };

    struct stat s;
    for (int i = 0; symlink_paths[i] != NULL; i++) {
        if (lstat(symlink_paths[i], &s) == 0) {
            if (S_ISLNK(s.st_mode)) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// MARK: - Restricted Write Check
// ============================================================================

bool aran_check_jailbreak_write(void) {
    // VAPT #14: fopen usage is intentional here — we test if the sandbox allows
    // writing to restricted paths (a jailbreak indicator). This is a detection
    // technique, not a data processing function.
    const char *test_paths[] = {
        "/private/jailbreak_aran_test.txt",
        "/private/var/tmp/aran_jb_test.txt",
        NULL
    };

    for (int i = 0; test_paths[i] != NULL; i++) {
        // Bounded path length check before fopen (VAPT #14 mitigation)
        if (strnlen(test_paths[i], 256) >= 256) continue;
        FILE *f = fopen(test_paths[i], "w");
        if (f) {
            fclose(f);
            remove(test_paths[i]);
            return true;
        }
    }

    return false;
}

// ============================================================================
// MARK: - Combined Scanner
// ============================================================================

uint32_t aran_scan_all(void) {
    uint32_t threats = ARAN_THREAT_NONE;

    if (_aran_sysctl_debugger_check())     threats |= ARAN_THREAT_DEBUGGER;
    if (aran_check_mach_ports())           threats |= ARAN_THREAT_DEBUGGER_MACH;
    if (aran_check_jailbreak_fs())         threats |= ARAN_THREAT_JAILBREAK_FS;
    if (aran_check_jailbreak_symlinks())   threats |= ARAN_THREAT_JAILBREAK_SYMLINK;
    if (aran_check_jailbreak_write())      threats |= ARAN_THREAT_JAILBREAK_WRITE;
    if (aran_check_shadow_cydia())         threats |= ARAN_THREAT_SHADOW_CYDIA;

    uint32_t dyld = aran_check_dyld_injections();
    threats |= dyld;

    if (aran_check_frida_port())           threats |= ARAN_THREAT_FRIDA_PORT;
    if (aran_check_dyld_environment())     threats |= ARAN_THREAT_DYLD_ENVVAR;
    if (aran_check_tty_attached())         threats |= ARAN_THREAT_TTY_ATTACHED;
    if (aran_check_ppid_suspicious())      threats |= ARAN_THREAT_PPID_SUSPICIOUS;
    if (aran_check_sandbox_violation())    threats |= ARAN_THREAT_SANDBOX_VIOLATION;

    return threats;
}

// ============================================================================
// MARK: - Shadow Cydia Detection (Bypass Resistant)
// ============================================================================

bool aran_check_shadow_cydia(void) {
    // Shadow Cydia hooks filesystem operations, so we use multiple detection methods

    // Method 1: Check for Shadow Cydia preference files using direct syscalls
    const char *shadow_paths[] = {
        "/var/mobile/Library/Preferences/com.shadow.shadowcydia.plist",
        "/var/mobile/Library/ShadowCydia",
        "/Library/MobileSubstrate/DynamicLibraries/Shadow.plist",
        NULL
    };

    for (int i = 0; shadow_paths[i] != NULL; i++) {
        // Use stat() which Shadow Cydia might hook, but also try alternative methods
        struct stat s;
        if (stat(shadow_paths[i], &s) == 0) {
            return true;
        }
    }

    // Method 2: Check for Shadow Cydia service process
    // Shadow Cydia runs as a background service
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "shadow") || strstr(line, "Shadow")) {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }

    // Method 3: Check for Shadow Cydia dylib in memory using dlsym
    void *handle = dlopen(NULL, RTLD_NOW);
    if (handle) {
        // Try to find Shadow Cydia symbols
        Dl_info info;
        if (dladdr(aran_check_shadow_cydia, &info)) {
            // Check the loaded modules for Shadow Cydia
            for (uint32_t i = 0; i < _dyld_image_count(); i++) {
                const char *name = _dyld_get_image_name(i);
                if (name && (strstr(name, "Shadow") || strstr(name, "shadow"))) {
                    dlclose(handle);
                    return true;
                }
            }
        }
        dlclose(handle);
    }

    return false;
}

// ============================================================================
// MARK: - Sandbox Integrity Check (App Store Safe)
// ============================================================================

bool aran_check_sandbox_violation(void) {
    // Attempt to write to a restricted path outside the app sandbox.
    // On a non-jailbroken device, fopen() will fail with EPERM.
    // On a jailbroken device, the sandbox is weakened and the write succeeds.
    // Uses only public POSIX fopen(3) — no private APIs.
    const char *path = "/private/jailbreak.txt";
    if (strnlen(path, 256) >= 256) return false;

    FILE *f = fopen(path, "w");
    if (f) {
        fclose(f);
        remove(path);
        return true;
    }
    return false;
}
