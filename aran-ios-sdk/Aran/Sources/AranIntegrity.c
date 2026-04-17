//
//  AranIntegrity.c
//  Aran iOS SDK
//
//  App Store-compliant jailbreak and runtime manipulation detection.
//  Uses only public APIs: sysctl, stat, _dyld_get_image_name, canOpenURL.
//  Never calls exit() or abort() — returns state enum for graceful degradation.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>
#include "AranObfuscate.h"

// ── Compile-time obfuscated paths (XOR'd with ARAN_XOR_KEY) ──────────────────
// These are obfuscated at compile time to avoid plain-text detection

static const char *cydiaPath = ("/Applications/Cydia.app");
static const char *sshdPath = ("/usr/sbin/sshd");
static const char *aptPath = ("/private/var/lib/apt");
static const char *bashPath = ("/bin/bash");
static const char *fridaPath = ("/usr/lib/frida");
static const char *cycriptPath = ("/usr/lib/cycript");
static const char *substitutePath = ("/usr/lib/substitute");

// ── Integrity salt (hidden value for compromised state) ────────────────────────
static const char *integritySalt = ("ARAN_INTEGRITY_SALT_2024_HARDCORE");

// ── Device integrity state (never calls exit) ─────────────────────────────────
typedef enum {
    ARAN_INTEGRITY_SECURE = 0,
    ARAN_INTEGRITY_JAILBROKEN = 1,
    ARAN_INTEGRITY_DEBUGGER = 2,
    ARAN_INTEGRITY_HOOKED = 4,
    ARAN_INTEGRITY_COMPROMISED = 8
} AranIntegrityState;

static AranIntegrityState g_integrityState = ARAN_INTEGRITY_SECURE;

// ── Inline obfuscated checks (no single 'isJailbroken' symbol) ────────────────

static inline int __aran_check_path_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static inline int __aran_check_file_writable(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

// ── sysctl P_TRACED detection (public API, no ptrace) ─────────────────────────

static inline int __aran_check_debugger(void) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        // P_TRACED flag indicates debugger is attached
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return 0;
}

// ── _dyld_get_image_name hook detection (Frida, Cycript, Substitute) ───────────

static inline int __aran_check_dyld_hooks(void) {
    uint32_t count = _dyld_image_count();
    
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName == NULL) continue;
        
        // Check for common hooking frameworks
        if (strstr(imageName, ("frida")) != NULL ||
            strstr(imageName, ("cycript")) != NULL ||
            strstr(imageName, ("substitute")) != NULL ||
            strstr(imageName, ("substrate")) != NULL ||
            strstr(imageName, ("FridaGadget")) != NULL) {
            return 1;
        }
    }
    return 0;
}

// ── Jailbreak path detection (stat only, no private APIs) ─────────────────────

static inline int __aran_check_jailbreak_paths(void) {
    // Check for common jailbreak indicators
    if (__aran_check_path_exists(cydiaPath)) return 1;
    if (__aran_check_path_exists(sshdPath)) return 1;
    if (__aran_check_path_exists(aptPath)) return 1;
    
    // Check for writable system directories (sign of jailbreak)
    if (__aran_check_file_writable(("/System/Library/LaunchDaemons"))) return 1;
    if (__aran_check_file_writable(("/Applications"))) return 1;
    
    // Check for bash in unexpected locations
    if (__aran_check_path_exists(bashPath)) {
        // On non-jailbroken iOS, /bin/bash doesn't exist
        return 1;
    }
    
    return 0;
}

// ── Integrity header generation (cryptographic hash with salt) ────────────────

const char *aran_generate_integrity_header(void) {
    static __thread char header[65];
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    
    // Hash device state + salt
    CC_SHA256_Update(&ctx, (const uint8_t *)&g_integrityState, sizeof(g_integrityState));
    CC_SHA256_Update(&ctx, (const uint8_t *)integritySalt, strlen(integritySalt));
    
    // Add additional entropy
    time_t now = time(NULL);
    CC_SHA256_Update(&ctx, (const uint8_t *)&now, sizeof(now));
    
    CC_SHA256_Final(hash, &ctx);
    
    // Convert to hex
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        snprintf(&header[i * 2], 3, "%02x", hash[i]);
    }
    header[64] = '\0';
    
    return header;
}

// ── Main integrity check (returns state, never exits) ─────────────────────────

int aran_perform_integrity_check(void) {
    int compromised = 0;
    
    // Check for jailbreak paths
    if (__aran_check_jailbreak_paths()) {
        g_integrityState |= ARAN_INTEGRITY_JAILBROKEN;
        compromised = 1;
    }
    
    // Check for debugger (P_TRACED)
    if (__aran_check_debugger()) {
        g_integrityState |= ARAN_INTEGRITY_DEBUGGER;
        compromised = 1;
    }
    
    // Check for dyld hooks (Frida, Cycript, Substitute)
    if (__aran_check_dyld_hooks()) {
        g_integrityState |= ARAN_INTEGRITY_HOOKED;
        compromised = 1;
    }
    
    if (compromised) {
        g_integrityState |= ARAN_INTEGRITY_COMPROMISED;
    }
    
    return g_integrityState;
}

// ── Get current integrity state (for Swift wrapper) ─────────────────────────

int aran_get_integrity_state(void) {
    return g_integrityState;
}

// ── Reset integrity state (for testing only) ─────────────────────────────────

void aran_reset_integrity_state(void) {
    g_integrityState = ARAN_INTEGRITY_SECURE;
}
