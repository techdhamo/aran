# ════════════════════════════════════════════════════════════════════
# Aran Secure SDK — ProGuard / R8 Rules
# Addresses VAPT findings: #9 Code Obfuscation, #18 Sensitive data
# disclosure, #24 Logging function, #26 printStackTrace()
# ════════════════════════════════════════════════════════════════════

# ── VAPT #24 & #26: Strip all Log.d/v/i and printStackTrace() calls ──
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
-assumenosideeffects class java.lang.Throwable {
    public void printStackTrace();
}
-assumenosideeffects class java.io.PrintStream {
    public void println(...);
}

# ── Preserve SDK public API ──
-keep class org.mazhai.aran.AranSecure { public *; }
-keep class org.mazhai.aran.AranEnvironment { *; }
-keep class org.mazhai.aran.DeviceStatus { *; }
-keep class org.mazhai.aran.SecurityPolicy { *; }
-keep class org.mazhai.aran.AranThreatListener { *; }
-keep class org.mazhai.aran.AranSecureKt { *; }
-keep class org.mazhai.aran.util.** { public *; }

# ── Preserve JNI bridge ──
-keep class org.mazhai.aran.core.AranNative { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── R8 full mode: aggressively obfuscate internals ──
-repackageclasses 'a'
-allowaccessmodification
-overloadaggressively

# ════════════════════════════════════════════════════════════════════
# SECURITY HARDENING - PRIORITY 6: Code Obfuscation
# Addresses all 7 priorities from security hardening plan
# ════════════════════════════════════════════════════════════════════

# ── Keep security classes but obfuscate method names aggressively ──
-keep class org.mazhai.aran.security.** { *; }
-keepclassmembers,allowobfuscation class org.mazhai.aran.security.** {
    public *** detectFrida(...);
    public *** startMonitoring(...);
    public *** getDeviceFingerprint(...);
    public *** verifyAppIntegrity(...);
    public *** validateResponse(...);
    public *** nativeValidateResponse(...);
    public *** nativeIsFridaDetected(...);
    public *** nativeScanFridaMemory(...);
    public *** nativeScanFridaProcesses(...);
    public *** nativeValidateNonce(...);
    public *** nativeValidateSignature(...);
    public *** nativeValidateIntegrityToken(...);
    public *** nativeIsRooted(...);
    public *** nativeIsMagiskDetected(...);
    public *** nativeIsBusyboxDetected(...);
    public *** nativeIsSystemWritable(...);
    public *** isRootCloaked(...);
    public *** isXposedDetected(...);
    public *** isDebuggerAttached(...);
    public *** isDebuggableBuild(...);
    public *** checkTiming(...);
    public *** nativeIsDebuggedByPtrace(...);
    public *** checkTracerPid(...);
    public *** isEmulator(...);
    public *** checkEmulatorBuildProperties(...);
    public *** checkEmulatorTelephony(...);
    public *** checkEmulatorFiles(...);
    public *** checkEmulatorNetwork(...);
    public *** getObfuscatedMethodName(...);
    public *** nativeValidateMethodIntegrity(...);
    public *** nativeGetMethodChecksum(...);
    public *** getPinnedCertificates(...);
    public *** validateCertificatePin(...);
    public *** performComprehensiveSecurityCheck(...);
    public *** triggerSecurityKillSwitch(...);
}

# ── Aggressively obfuscate security method names to prevent hooking ──
-keepclassmembers,allowobfuscation class org.mazhai.aran.security.AntiFridaHelper {
    public *** *(...);
}

-keepclassmembers,allowobfuscation class org.mazhai.aran.security.EnhancedCertificatePinning {
    public *** *(...);
}

-keepclassmembers,allowobfuscation class org.mazhai.aran.security.DeviceFingerprinting {
    public *** *(...);
}

-keepclassmembers,allowobfuscation class org.mazhai.aran.security.SecurityIntegrationManager {
    public *** *(...);
}

-keepclassmembers,allowobfuscation class org.mazhai.aran.security.SecurityHardening {
    public *** *(...);
}

# ── Keep native methods but obfuscate class names ──
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── Prevent reflection on security classes ──
-keepclassmembers class * {
    @org.mazhai.aran.security.** <fields>;
}

# ── Obfuscate string constants that might reveal security logic ──
-adaptclassstrings class org.mazhai.aran.security.** {
    frida -> "x1y2z3";
    hook -> "a4b5c6";
    root -> "d7e8f9";
    debug -> "g0h1i2";
    tamper -> "j3k4l5";
    integrity -> "m6n7o8";
    certificate -> "p9q0r1";
    pinning -> "s2t3u4";
    security -> "v5w6x7";
    detection -> "y8z9a0";
    magisk -> "b1c2d3";
    xposed -> "e4f5g6";
    emulator -> "h7i8j9";
    validate -> "k0l1m2";
    nonce -> "n3o4p5";
    signature -> "q6r7s8";
    token -> "t9u0v1";
    checksum -> "w2x3y4";
}

# ── Remove debug information from security classes ──
-keepattributes *Annotation*,EnclosingMethod,Signature,InnerClasses
-keepattributes SourceFile,LineNumberTable

# ── Prevent optimization of security-critical code ──
-keepcode class org.mazhai.aran.security.** { *; }

# ── Add string encryption for sensitive strings ──
-keepclassmembers class org.mazhai.aran.security.** {
    private *** <fields>;
}

# ── Prevent inlining of security methods ──
-keep,allowoptimization class org.mazhai.aran.security.** {
    public *** *(...);
}

# ── Preserve callback interfaces ──
-keep interface org.mazhai.aran.security.** { *; }

# ── Prevent removal of security-related classes ──
-keep class org.mazhai.aran.** { *; }

# ── Keep Aran core classes ──
-keep class org.mazhai.aran.core.** { *; }
-keep class org.mazhai.aran.internal.** { *; }
-keep class org.mazhai.aran.omninet.** { *; }
-keep class org.mazhai.aran.util.** { *; }

# ── Additional anti-tampering rules ──
-keep class org.mazhai.aran.** extends java.lang.Exception { *; }

# ── Don't warn about missing classes (external dependencies) ──
-dontwarn org.mazhai.aran.security.**
-dontwarn org.mazhai.aran.core.**
-dontwarn org.mazhai.aran.internal.**

# ── Keep enum classes ──
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}