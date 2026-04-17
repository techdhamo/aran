#include <jni.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>

static bool fileExists(const char* path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}

static bool aran_string_equals_ignore_case(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

static std::string aran_trim_ascii(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

static bool aran_frida_maps_detected() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    const char* kNeedles[] = {
        "frida-agent",
        "frida-gadget",
        "gum-js",
        "gadget.so",
        "frida",
        "gmain",
        "linjector"
    };
    std::string line;
    while (std::getline(maps, line)) {
        for (const char* needle : kNeedles) {
            if (line.find(needle) != std::string::npos) return true;
        }
    }
    return false;
}

// Probe frida default listener on localhost:27042 (decoded from legacy lsof | grep frida-server)
static bool aran_frida_port_scan() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Set non-blocking for fast timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) { close(sock); return true; }

    if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        struct timeval tv{0, 100000}; // 100ms timeout
        if (select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) { close(sock); return true; }
        }
    }
    close(sock);
    return false;
}

static bool isFridaDetected() {
    return aran_frida_maps_detected() || aran_frida_port_scan();
}

// Parse /proc/self/status for TracerPid (decoded from legacy debugger detection)
static bool aran_tracer_pid_check() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return false;
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0 || line.find("TracerPid:\t") != std::string::npos) {
            // Extract the PID value after "TracerPid:"
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                std::string val = aran_trim_ascii(line.substr(pos + 1));
                if (!val.empty() && val != "0") return true;
            }
        }
    }
    return false;
}

// JNI: android.os.Debug.isDebuggerConnected() (from legacy Java-level debugger check)
static bool aran_debugger_connected_jni(JNIEnv* env) {
    jclass debugCls = env->FindClass("android/os/Debug");
    if (!debugCls) { env->ExceptionClear(); return false; }
    jmethodID isConnected = env->GetStaticMethodID(debugCls, "isDebuggerConnected", "()Z");
    if (!isConnected) { env->ExceptionClear(); return false; }
    return env->CallStaticBooleanMethod(debugCls, isConnected);
}

static bool isDebuggerAttached(JNIEnv* env) {
    // 1. ptrace TRACEME — fails if already being traced
    errno = 0;
    long rc = ptrace(PTRACE_TRACEME, 0, 1, 0);
    if (rc == -1) return true;

    // 2. TracerPid in /proc/self/status
    if (aran_tracer_pid_check()) return true;

    // 3. JNI: Debug.isDebuggerConnected()
    if (aran_debugger_connected_jni(env)) return true;

    return false;
}

static bool aran_is_rooted_artifacts() {
    static const char* kPaths[] = {
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/sbin/magisk",
        "/init.magisk.rc",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        // Magisk v28+ (6.2.3-Beta)
        "/data/adb/magisk/magisk64",
        "/data/adb/magisk/magiskinit",
        "/data/adb/magisk/busybox",
        "/data/adb/magisk/magiskboot",
        "/data/adb/post-fs-data.d",
        "/data/adb/service.d",
        // KernelSU (6.2.0-Beta)
        "/data/adb/ksu",
        "/data/adb/ksu/bin/ksud",
        "/data/adb/ksu/bin/busybox",
        "/data/adb/ksud",
        // APatch (6.2.1-Beta)
        "/data/adb/apatch",
        "/data/adb/apd",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/system/xbin/daemonsu",
        "/system/bin/daemonsu",
        "/system/etc/init.d/99telecominfra",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu"
    };

    for (const char* p : kPaths) {
        if (fileExists(p)) return true;
    }

    // Magisk service properties (decoded from legacy static initializer + v28 updates)
    const char* kMagiskProps[] = {
        "init.svc.magisk_pfs",
        "init.svc.magisk_pfsd",
        "init.svc.magisk_service",
        "persist.magisk.hide",
        "ro.magisk.zygisk",
        "ro.kernelsu.version",
        "init.svc.kernelsu"
    };
    for (const char* p : kMagiskProps) {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get(p, value) > 0) return true;
    }

    // ro.debuggable == 1 indicates userdebug/eng build
    {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.debuggable", value) > 0 && std::string(value) == "1") {
            char secure[PROP_VALUE_MAX] = {0};
            if (__system_property_get("ro.secure", secure) > 0 && std::string(secure) == "0") {
                return true;
            }
        }
    }

    // SELinux permissive mode check
    {
        std::ifstream enforce("/sys/fs/selinux/enforce");
        if (enforce.is_open()) {
            char c = '1';
            enforce.get(c);
            if (c == '0') return true; // permissive = likely rooted
        }
    }

    return false;
}

// Check Build.TAGS for "test-keys" via JNI (indicates non-release firmware)
static bool aran_check_build_tags(JNIEnv* env) {
    jclass buildCls = env->FindClass("android/os/Build");
    if (!buildCls) { env->ExceptionClear(); return false; }
    jfieldID tagsField = env->GetStaticFieldID(buildCls, "TAGS", "Ljava/lang/String;");
    if (!tagsField) { env->ExceptionClear(); return false; }
    auto tags = (jstring)env->GetStaticObjectField(buildCls, tagsField);
    if (!tags) return false;
    const char* raw = env->GetStringUTFChars(tags, nullptr);
    if (!raw) return false;
    bool found = std::string(raw).find("test-keys") != std::string::npos;
    env->ReleaseStringUTFChars(tags, raw);
    return found;
}

static bool aran_detect_hooks() {
    // 1. File-based check: XposedBridge.jar (decoded from legacy)
    if (fileExists("/system/framework/XposedBridge.jar")) return true;

    // 2. /proc/self/maps scan for hook framework shared objects
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    const char* kHookNeedles[] = {
        "xposed",
        "lsposed",
        "edxposed",
        "substrate",
        "frida",
        "riru",
        "zygisk",
        "sandhook",
        "epic",
        "whale",
        "pine",
        "cydia",
        "libsubstrate",
        "XposedBridge",
        "libzygisk",
        "zygisk_companion",
        "zygisk_loader",
        "magisk_zygisk",
        "kernelsu",
        "ksud",
        "apatch",
        "apd"
    };

    std::string line;
    while (std::getline(maps, line)) {
        // Convert to lowercase for case-insensitive matching
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c){ return std::tolower(c); });
        for (const char* needle : kHookNeedles) {
            if (lower.find(needle) != std::string::npos) return true;
        }
    }
    return false;
}

static bool aran_prop_contains(const char* propName, const char* needle) {
    char value[PROP_VALUE_MAX] = {0};
    int n = __system_property_get(propName, value);
    if (n <= 0) return false;
    std::string v(value);
    return v.find(needle) != std::string::npos;
}

static bool aran_prop_equals(const char* propName, const char* expected) {
    char value[PROP_VALUE_MAX] = {0};
    int n = __system_property_get(propName, value);
    if (n <= 0) return false;
    return std::string(value) == expected;
}

// JNI helper: read a static String field from android.os.Build
static std::string aran_get_build_field(JNIEnv* env, const char* fieldName) {
    jclass buildCls = env->FindClass("android/os/Build");
    if (!buildCls) { env->ExceptionClear(); return ""; }
    jfieldID fid = env->GetStaticFieldID(buildCls, fieldName, "Ljava/lang/String;");
    if (!fid) { env->ExceptionClear(); return ""; }
    auto jstr = (jstring)env->GetStaticObjectField(buildCls, fid);
    if (!jstr) return "";
    const char* raw = env->GetStringUTFChars(jstr, nullptr);
    if (!raw) return "";
    std::string result(raw);
    env->ReleaseStringUTFChars(jstr, raw);
    return result;
}

static bool aran_str_contains_ic(const std::string& haystack, const char* needle) {
    std::string h = haystack, n(needle);
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return std::tolower(c); });
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c){ return std::tolower(c); });
    return h.find(n) != std::string::npos;
}

static bool aran_detect_emulator_props() {
    // Legacy-derived property keys (decoded from C0198 static initializer)
    static const char* kGoldfishProps[] = {
        "ro.hardware",
        "ro.boot.hardware",
        "ro.hardware.audio.primary"
    };
    for (const char* p : kGoldfishProps) {
        if (aran_prop_equals(p, "goldfish")) return true;
    }

    if (aran_prop_equals("ro.build.product", "google_sdk")) return true;
    if (aran_prop_contains("ro.build.product", "sdk_google")) return true;
    if (aran_prop_contains("ro.kernel.androidboot.hardware", "goldfish")) return true;

    // ro.hardware.virtual_device and ro.factorytest (decoded from legacy)
    {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.hardware.virtual_device", value) > 0) return true;
        if (__system_property_get("ro.factorytest", value) > 0 && std::string(value) != "0") return true;
    }

    // Service props decoded from legacy C0198 static initializer
    static const char* kServiceProps[] = {
        "init.svc.qemud",
        "init.svc.goldfish-setup",
        "init.svc.goldfish-logcat",
        "init.svc.vbox86-setup",
        "init.svc.gce_fs_monitor",
        "init.svc.dempeventlog",
        "init.svc.dumpipclog",
        "init.svc.dumplogcat",
        "init.svc.dumplogcat-efs",
        "init.svc.filemon",
        "qemu.sf.fake_camera"
    };
    for (const char* p : kServiceProps) {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get(p, value) > 0) return true;
    }

    // File-based artifacts decoded from legacy
    static const char* kEmuFiles[] = {
        "/sdcard/windows/BstSharedFolder",
        "/mnt/windows/BstSharedFolder",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    };
    for (const char* p : kEmuFiles) {
        if (fileExists(p)) return true;
    }

    return false;
}

// Full Build.* field checks (decoded from legacy C0016 emulator detector m88-m108)
static bool aran_detect_emulator_build(JNIEnv* env) {
    // MANUFACTURER indicators (decoded from C0198.f792 via C0016.m88)
    static const char* kManufacturers[] = { "BlueStacks", "Nox Player", "Genymotion", "TiantianVM" };
    std::string manufacturer = aran_get_build_field(env, "MANUFACTURER");
    for (const char* s : kManufacturers) {
        if (aran_str_contains_ic(manufacturer, s)) return true;
    }

    // BRAND indicators (decoded from C0198.f793 via C0016.m89)
    static const char* kBrands[] = { "generic_x86", "Genymotion", "TiantianVM", "generic" };
    std::string brand = aran_get_build_field(env, "BRAND");
    for (const char* s : kBrands) {
        if (aran_str_contains_ic(brand, s)) return true;
    }

    // PRODUCT indicators (decoded from C0198.f791 via C0016.m105)
    static const char* kProducts[] = {
        "sdk_google", "google_sdk", "generic_x86", "sdk_gphone",
        "sdk_google_phone_x86", "vbox86p", "nox", "emu64a"
    };
    std::string product = aran_get_build_field(env, "PRODUCT");
    for (const char* s : kProducts) {
        if (aran_str_contains_ic(product, s)) return true;
    }

    // DEVICE indicators (decoded from C0198.f797 via C0016.m90)
    static const char* kDevices[] = { "generic_x86", "ttVM_Hdragon", "generic", "emu64a" };
    std::string device = aran_get_build_field(env, "DEVICE");
    for (const char* s : kDevices) {
        if (aran_str_contains_ic(device, s)) return true;
    }

    // MODEL indicators (decoded from C0198.f798 via C0016.m91)
    static const char* kModels[] = {
        "Android SDK built for x86_64", "Android SDK built for x86",
        "Emulator", "sdk_gphone", "sdk_google_phone_x86", "sdk_gphone64_arm64"
    };
    std::string model = aran_get_build_field(env, "MODEL");
    for (const char* s : kModels) {
        if (aran_str_contains_ic(model, s)) return true;
    }

    // HARDWARE indicators (decoded from C0198.f799 via C0016.m92)
    static const char* kHardware[] = { "goldfish", "ttVM_x86", "ttVM_Hdragon", "ranchu", "vbox86" };
    std::string hardware = aran_get_build_field(env, "HARDWARE");
    for (const char* s : kHardware) {
        if (aran_str_contains_ic(hardware, s)) return true;
    }

    // FINGERPRINT indicators (decoded from C0198.f800 via C0016.m93)
    static const char* kFingerprints[] = { "generic_x86", "generic_x86_64", "google_sdk", "generic/vbox86p" };
    std::string fingerprint = aran_get_build_field(env, "FINGERPRINT");
    for (const char* s : kFingerprints) {
        if (aran_str_contains_ic(fingerprint, s)) return true;
    }

    // BOARD contains "nox" (decoded from C0016.m106)
    std::string board = aran_get_build_field(env, "BOARD");
    if (aran_str_contains_ic(board, "nox")) return true;

    // BOOTLOADER contains "nox" (decoded from C0016.m107)
    std::string bootloader = aran_get_build_field(env, "BOOTLOADER");
    if (aran_str_contains_ic(bootloader, "nox")) return true;

    // SERIAL contains "nox" (decoded from C0016.m108)
    std::string serial = aran_get_build_field(env, "SERIAL");
    if (aran_str_contains_ic(serial, "nox") || aran_str_contains_ic(serial, "unknown")) return true;

    return false;
}

static bool aran_detect_emulator(JNIEnv* env) {
    return aran_detect_emulator_props() || aran_detect_emulator_build(env);
}

static bool aran_verify_signature(JNIEnv* env, jstring expectedSignatureSha256) {
    if (expectedSignatureSha256 == nullptr) {
        return true;
    }

    const char* expectedRaw = env->GetStringUTFChars(expectedSignatureSha256, nullptr);
    if (expectedRaw == nullptr) {
        return true;
    }
    std::string expected = aran_trim_ascii(std::string(expectedRaw));
    env->ReleaseStringUTFChars(expectedSignatureSha256, expectedRaw);
    if (expected.empty()) {
        return true;
    }

    // Obtain Application context via ActivityThread.currentApplication().
    jclass activityThread = env->FindClass("android/app/ActivityThread");
    if (!activityThread) return false;
    jmethodID currentApplication = env->GetStaticMethodID(activityThread, "currentApplication", "()Landroid/app/Application;");
    if (!currentApplication) return false;
    jobject application = env->CallStaticObjectMethod(activityThread, currentApplication);
    if (!application) return false;

    jclass contextCls = env->FindClass("android/content/Context");
    jmethodID getPackageManager = env->GetMethodID(contextCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID getPackageName = env->GetMethodID(contextCls, "getPackageName", "()Ljava/lang/String;");
    if (!getPackageManager || !getPackageName) return false;
    jobject pm = env->CallObjectMethod(application, getPackageManager);
    jstring pkg = (jstring)env->CallObjectMethod(application, getPackageName);
    if (!pm || !pkg) return false;

    jclass pmCls = env->FindClass("android/content/pm/PackageManager");
    jmethodID getPackageInfo = env->GetMethodID(pmCls, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfo) return false;

    // 0x08000000 = GET_SIGNING_CERTIFICATES, 0x40 = GET_SIGNATURES (legacy)
    const jint flags = 0x08000000;
    jobject pkgInfo = env->CallObjectMethod(pm, getPackageInfo, pkg, flags);
    if (!pkgInfo) {
        // fallback
        pkgInfo = env->CallObjectMethod(pm, getPackageInfo, pkg, (jint)0x40);
        if (!pkgInfo) return false;
    }

    jclass pkgInfoCls = env->GetObjectClass(pkgInfo);
    jfieldID signingInfoField = env->GetFieldID(pkgInfoCls, "signingInfo", "Landroid/content/pm/SigningInfo;");
    jfieldID signaturesField = env->GetFieldID(pkgInfoCls, "signatures", "[Landroid/content/pm/Signature;");

    jobjectArray sigArr = nullptr;
    if (signingInfoField) {
        jobject signingInfo = env->GetObjectField(pkgInfo, signingInfoField);
        if (signingInfo) {
            jclass signingInfoCls = env->GetObjectClass(signingInfo);
            jmethodID getApkContentsSigners = env->GetMethodID(signingInfoCls, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            if (getApkContentsSigners) {
                sigArr = (jobjectArray)env->CallObjectMethod(signingInfo, getApkContentsSigners);
            }
        }
    }
    if (!sigArr && signaturesField) {
        sigArr = (jobjectArray)env->GetObjectField(pkgInfo, signaturesField);
    }
    if (!sigArr || env->GetArrayLength(sigArr) < 1) return false;

    jobject sig0 = env->GetObjectArrayElement(sigArr, 0);
    if (!sig0) return false;
    jclass sigCls = env->FindClass("android/content/pm/Signature");
    jmethodID toByteArray = env->GetMethodID(sigCls, "toByteArray", "()[B");
    if (!toByteArray) return false;
    jbyteArray certBytes = (jbyteArray)env->CallObjectMethod(sig0, toByteArray);
    if (!certBytes) return false;

    jclass mdCls = env->FindClass("java/security/MessageDigest");
    jmethodID getInstance = env->GetStaticMethodID(mdCls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jmethodID digest = env->GetMethodID(mdCls, "digest", "([B)[B");
    if (!getInstance || !digest) return false;

    jstring sha256Str = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInstance, sha256Str);
    if (!md) return false;
    jbyteArray hash = (jbyteArray)env->CallObjectMethod(md, digest, certBytes);
    if (!hash) return false;

    jsize hashLen = env->GetArrayLength(hash);
    jbyte* hashBytes = env->GetByteArrayElements(hash, nullptr);
    if (!hashBytes) return false;

    static const char* kHex = "0123456789abcdef";
    std::string actual;
    actual.reserve((size_t)hashLen * 2);
    for (jsize i = 0; i < hashLen; i++) {
        unsigned char c = static_cast<unsigned char>(hashBytes[i]);
        actual.push_back(kHex[(c >> 4) & 0x0F]);
        actual.push_back(kHex[c & 0x0F]);
    }
    env->ReleaseByteArrayElements(hash, hashBytes, JNI_ABORT);

    // Normalize expected: lower + remove ':' if present.
    std::string expectedNorm;
    expectedNorm.reserve(expected.size());
    for (char ch : expected) {
        if (ch == ':') continue;
        expectedNorm.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    return aran_string_equals_ignore_case(actual, expectedNorm);
}

// ────────────────────────────────────────────────────────────────────
// JNI helper: obtain Application context via ActivityThread.currentApplication()
// ────────────────────────────────────────────────────────────────────
static jobject aran_get_application(JNIEnv* env) {
    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (!atCls) { env->ExceptionClear(); return nullptr; }
    jmethodID curApp = env->GetStaticMethodID(atCls, "currentApplication", "()Landroid/app/Application;");
    if (!curApp) { env->ExceptionClear(); return nullptr; }
    return env->CallStaticObjectMethod(atCls, curApp);
}

// ────────────────────────────────────────────────────────────────────
// Untrusted installer detection (decoded from legacy getInstallerPackageName logic)
// Returns true if the app was NOT installed from a trusted store.
// ────────────────────────────────────────────────────────────────────
static bool aran_check_untrusted_installer(JNIEnv* env) {
    jobject app = aran_get_application(env);
    if (!app) return false;

    jclass ctxCls = env->FindClass("android/content/Context");
    jmethodID getPM = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID getPkg = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    if (!getPM || !getPkg) { env->ExceptionClear(); return false; }

    jobject pm = env->CallObjectMethod(app, getPM);
    auto pkgName = (jstring)env->CallObjectMethod(app, getPkg);
    if (!pm || !pkgName) return false;

    std::string installer;

    // API 30+: getInstallSourceInfo().getInitiatingPackageName()
    jclass pmCls = env->GetObjectClass(pm);
    jmethodID getISI = env->GetMethodID(pmCls, "getInstallSourceInfo",
        "(Ljava/lang/String;)Landroid/content/pm/InstallSourceInfo;");
    if (getISI && !env->ExceptionCheck()) {
        jobject isi = env->CallObjectMethod(pm, getISI, pkgName);
        if (env->ExceptionCheck()) { env->ExceptionClear(); isi = nullptr; }
        if (isi) {
            jclass isiCls = env->GetObjectClass(isi);
            jmethodID getInit = env->GetMethodID(isiCls, "getInitiatingPackageName", "()Ljava/lang/String;");
            if (getInit) {
                auto jInstaller = (jstring)env->CallObjectMethod(isi, getInit);
                if (jInstaller) {
                    const char* r = env->GetStringUTFChars(jInstaller, nullptr);
                    if (r) { installer = r; env->ReleaseStringUTFChars(jInstaller, r); }
                }
            }
        }
    } else {
        env->ExceptionClear();
    }

    // Fallback: getInstallerPackageName()
    if (installer.empty()) {
        jmethodID getIPN = env->GetMethodID(pmCls, "getInstallerPackageName",
            "(Ljava/lang/String;)Ljava/lang/String;");
        if (getIPN && !env->ExceptionCheck()) {
            auto jInstaller = (jstring)env->CallObjectMethod(pm, getIPN, pkgName);
            if (env->ExceptionCheck()) { env->ExceptionClear(); jInstaller = nullptr; }
            if (jInstaller) {
                const char* r = env->GetStringUTFChars(jInstaller, nullptr);
                if (r) { installer = r; env->ReleaseStringUTFChars(jInstaller, r); }
            }
        } else {
            env->ExceptionClear();
        }
    }

    // Empty installer = sideloaded
    if (installer.empty()) return true;

    // Trusted stores whitelist
    static const char* kTrusted[] = {
        "com.android.vending",           // Google Play
        "com.amazon.venezia",            // Amazon Appstore
        "com.huawei.appmarket",          // Huawei AppGallery
        "com.sec.android.app.samsungapps", // Samsung Galaxy Store
        "com.xiaomi.market",             // Xiaomi GetApps
        "com.oppo.market",              // OPPO App Market
        "com.bbk.appstore",            // Vivo App Store
        "com.heytap.market"             // OnePlus/realme Store
    };
    for (const char* t : kTrusted) {
        if (installer == t) return false;
    }
    return true; // installed from untrusted source
}

// ────────────────────────────────────────────────────────────────────
// Developer mode detection (decoded from legacy Settings.Secure check)
// Checks: development_settings_enabled
// ────────────────────────────────────────────────────────────────────
static bool aran_check_developer_mode(JNIEnv* env) {
    jobject app = aran_get_application(env);
    if (!app) return false;

    jclass ctxCls = env->FindClass("android/content/Context");
    jmethodID getCR = env->GetMethodID(ctxCls, "getContentResolver",
        "()Landroid/content/ContentResolver;");
    if (!getCR) { env->ExceptionClear(); return false; }
    jobject cr = env->CallObjectMethod(app, getCR);
    if (!cr) return false;

    jclass secureCls = env->FindClass("android/provider/Settings$Secure");
    if (!secureCls) { env->ExceptionClear(); return false; }
    jmethodID getInt = env->GetStaticMethodID(secureCls, "getInt",
        "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");
    if (!getInt) { env->ExceptionClear(); return false; }

    jstring key = env->NewStringUTF("development_settings_enabled");
    jint val = env->CallStaticIntMethod(secureCls, getInt, cr, key, (jint)0);
    return val == 1;
}

// ────────────────────────────────────────────────────────────────────
// ADB enabled detection (decoded from legacy Settings.Secure check)
// Checks: adb_enabled
// ────────────────────────────────────────────────────────────────────
static bool aran_check_adb_enabled(JNIEnv* env) {
    jobject app = aran_get_application(env);
    if (!app) return false;

    jclass ctxCls = env->FindClass("android/content/Context");
    jmethodID getCR = env->GetMethodID(ctxCls, "getContentResolver",
        "()Landroid/content/ContentResolver;");
    if (!getCR) { env->ExceptionClear(); return false; }
    jobject cr = env->CallObjectMethod(app, getCR);
    if (!cr) return false;

    jclass secureCls = env->FindClass("android/provider/Settings$Secure");
    if (!secureCls) { env->ExceptionClear(); return false; }
    jmethodID getInt = env->GetStaticMethodID(secureCls, "getInt",
        "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");
    if (!getInt) { env->ExceptionClear(); return false; }

    jstring key = env->NewStringUTF("adb_enabled");
    jint val = env->CallStaticIntMethod(secureCls, getInt, cr, key, (jint)0);
    return val == 1;
}

// ────────────────────────────────────────────────────────────────────
// #43 Environment Variable Tampering
// Detects LD_PRELOAD / LD_LIBRARY_PATH injection used by DBI frameworks
// ────────────────────────────────────────────────────────────────────
static bool aran_check_env_tampering() {
    // VAPT #14: Use strnlen for bounded string check
    const char* ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strnlen(ld_preload, 4096) > 0) return true;

    const char* ld_lib = getenv("LD_LIBRARY_PATH");
    if (ld_lib) {
        std::string val(ld_lib);
        if (val.find("/data/local/tmp") != std::string::npos ||
            val.find("frida") != std::string::npos ||
            val.find("xposed") != std::string::npos ||
            val.find("substrate") != std::string::npos) {
            return true;
        }
    }

    const char* classpath = getenv("CLASSPATH");
    if (classpath) {
        std::string val(classpath);
        if (val.find("XposedBridge") != std::string::npos ||
            val.find("lsposed") != std::string::npos ||
            val.find("edxposed") != std::string::npos) {
            return true;
        }
    }

    const char* zygisk_env = getenv("ZYGISK_ENABLED");
    if (zygisk_env && strnlen(zygisk_env, 16) > 0) return true;

    return false;
}

// ────────────────────────────────────────────────────────────────────
// #44 Runtime Integrity Check
// Scans /proc/self/maps for injected .so from suspicious paths
// (DBI frameworks inject from /data/local/tmp or /data/app writable dirs)
// ────────────────────────────────────────────────────────────────────
static bool aran_check_runtime_integrity() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    const char* kSuspiciousPaths[] = {
        "/data/local/tmp/",
        "/data/data/com.topjohnwu.magisk/",
        "/data/user_de/",
        "/sdcard/",
        "/storage/emulated/0/Download/"
    };

    std::string line;
    while (std::getline(maps, line)) {
        // Only check executable mappings (.so files)
        if (line.find(".so") == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos && line.find("r--p") == std::string::npos) continue;

        for (const char* sus : kSuspiciousPaths) {
            if (line.find(sus) != std::string::npos) return true;
        }
    }
    return false;
}

// ────────────────────────────────────────────────────────────────────
// #11 Proxy Detection
// Checks JVM system properties for configured HTTP/HTTPS proxies
// (VAPT finding: MitM via proxy interception)
// ────────────────────────────────────────────────────────────────────
static bool aran_check_proxy(JNIEnv* env) {
    jclass sysCls = env->FindClass("java/lang/System");
    if (!sysCls) { env->ExceptionClear(); return false; }
    jmethodID getProp = env->GetStaticMethodID(sysCls, "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;");
    if (!getProp) { env->ExceptionClear(); return false; }

    const char* kProxyKeys[] = {
        "http.proxyHost", "https.proxyHost", "socksProxyHost"
    };
    for (const char* key : kProxyKeys) {
        jstring jkey = env->NewStringUTF(key);
        auto jval = (jstring)env->CallStaticObjectMethod(sysCls, getProp, jkey);
        if (jval) {
            const char* raw = env->GetStringUTFChars(jval, nullptr);
            if (raw && strlen(raw) > 0) {
                env->ReleaseStringUTFChars(jval, raw);
                return true;
            }
            if (raw) env->ReleaseStringUTFChars(jval, raw);
        }
    }
    return false;
}

// ────────────────────────────────────────────────────────────────────
// 6.2.0-Beta: Zygisk Detection (experimental)
// Detects Magisk Zygisk, KernelSU Zygisk, and module injection
// ────────────────────────────────────────────────────────────────────
static bool aran_detect_zygisk() {
    // 1. Check for Zygisk module directories
    const char* kZygiskPaths[] = {
        "/data/adb/modules/.zygisk",
        "/data/adb/lspd/config/modules",
        "/data/adb/modules/.core/zygisk",
        "/data/adb/magisk/zygisk"
    };
    for (const char* p : kZygiskPaths) {
        if (fileExists(p)) return true;
    }

    // 2. Check /proc/self/maps for Zygisk-injected libraries
    std::ifstream maps("/proc/self/maps");
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            std::string lower = line;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c){ return std::tolower(c); });
            if (lower.find("zygisk") != std::string::npos ||
                lower.find("libzygisk") != std::string::npos ||
                lower.find("zygisk_companion") != std::string::npos) {
                return true;
            }
        }
    }

    // 3. Check for Zygisk mount namespace artifacts
    std::ifstream mounts("/proc/self/mountinfo");
    if (mounts.is_open()) {
        std::string line;
        while (std::getline(mounts, line)) {
            if (line.find("magisk") != std::string::npos ||
                line.find("mirror") != std::string::npos) {
                if (line.find("/data/adb") != std::string::npos) return true;
            }
        }
    }

    return false;
}

// ────────────────────────────────────────────────────────────────────
// bit 13 (0x2000): Anonymous Memory ELF Scanning
// Zygisk / advanced root hiders unmap their files after injection
// so no path shows in /proc/self/maps. They leave anonymous regions
// with r-xp permissions that still carry an ELF magic header.
// ────────────────────────────────────────────────────────────────────
#include <sys/mman.h>

static bool aran_scan_anon_elf() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        // Only anonymous executable regions (no file path after the 5th field)
        if (line.find("r-xp") == std::string::npos) continue;
        // A file-backed mapping has a non-empty path; anonymous ends with spaces only
        // Format: addr perm offset dev inode [path]
        // Find the inode field (5th token) and see if anything follows
        size_t col = 0; int token = 0;
        while (col < line.size() && token < 5) {
            while (col < line.size() && line[col] == ' ') col++;
            while (col < line.size() && line[col] != ' ') col++;
            token++;
        }
        // Skip trailing spaces
        while (col < line.size() && line[col] == ' ') col++;
        if (col < line.size()) continue; // has a file path → skip

        // Parse start address
        unsigned long start = 0, end = 0;
        if (sscanf(line.c_str(), "%lx-%lx", &start, &end) != 2) continue;
        size_t region_size = end - start;
        if (region_size < 4) continue;

        // Peek at first 4 bytes without mapping again — use /proc/self/mem
        int mem_fd = open("/proc/self/mem", O_RDONLY);
        if (mem_fd < 0) continue;
        unsigned char magic[4] = {0};
        if (pread(mem_fd, magic, 4, static_cast<off_t>(start)) == 4) {
            // ELF magic: 0x7F 'E' 'L' 'F'
            if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                close(mem_fd);
                return true;
            }
        }
        close(mem_fd);
    }
    return false;
}

// ────────────────────────────────────────────────────────────────────
// bit 14 (0x4000): Zygisk File-Descriptor Leak Detection
// Zygisk hooks zygote and passes a companion socket FD into the
// child process. This FD is inherited but has no file path in
// /proc/self/fd — its symlink resolves to "socket:[inode]" while
// a legitimate app should have no extra inherited Unix sockets
// from zygote beyond the standard set (binder, logd, etc.).
// We count anonymous Unix sockets whose FD number is unusually low
// (inherited from zygote pre-exec) as a signal.
// ────────────────────────────────────────────────────────────────────
static bool aran_detect_zygisk_fd() {
    // Enumerate /proc/self/fd
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return false;

    int suspicious = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        int fd_num = atoi(ent->d_name);
        // Zygisk companion FDs are typically low-numbered (< 20) and inherited
        if (fd_num < 3 || fd_num > 20) continue;

        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd_num);
        char link_target[256] = {0};
        ssize_t len = readlink(fd_path, link_target, sizeof(link_target) - 1);
        if (len <= 0) continue;
        link_target[len] = '\0';

        // Anonymous Unix socket → "socket:[inode]" with no registered name
        if (strncmp(link_target, "socket:", 7) == 0) {
            // Check /proc/self/net/unix for this inode; if absent it is hidden
            std::string inode_str = std::string(link_target + 7);
            inode_str.erase(0, inode_str.find_first_not_of("[]"));
            inode_str.erase(inode_str.find_last_not_of("[]") + 1);

            std::ifstream unix_sock("/proc/self/net/unix");
            bool found_in_table = false;
            std::string uline;
            while (std::getline(unix_sock, uline)) {
                if (uline.find(inode_str) != std::string::npos) {
                    // If the path column is empty → anonymous socket
                    found_in_table = true;
                    // Anonymous unix sockets have no path after the inode column
                    size_t inode_pos = uline.find(inode_str);
                    std::string after = uline.substr(inode_pos + inode_str.size());
                    // Strip whitespace
                    size_t p = 0;
                    while (p < after.size() && after[p] == ' ') p++;
                    if (p >= after.size() || after[p] == '\n') {
                        suspicious++;
                    }
                    break;
                }
            }
            if (!found_in_table) {
                // Socket inode not in our net/unix table → hidden by Zygisk
                suspicious++;
            }
        }
    }
    closedir(dir);
    // More than 1 suspicious inherited anonymous socket is a strong signal
    return suspicious > 1;
}

// ════════════════════════════════════════════════════════════════════
// JNI BRIDGE — 15-bit expanded bitmask
// ════════════════════════════════════════════════════════════════════
extern "C" JNIEXPORT jint JNICALL
Java_org_mazhai_aran_core_AranNative_checkIntegrityNative(JNIEnv* env, jobject thiz, jstring expectedSignatureSha256) {
    (void) thiz;

    // bit 0  (0x001): rooted
    // bit 1  (0x002): frida
    // bit 2  (0x004): debugger
    // bit 3  (0x008): emulator
    // bit 4  (0x010): hooked
    // bit 5  (0x020): tampered (signature mismatch)
    // bit 6  (0x040): untrusted installer
    // bit 7  (0x080): developer mode enabled
    // bit 8  (0x100): ADB enabled
    // bit 9  (0x200): environment variable tampering
    // bit 10 (0x400): runtime integrity failure
    // bit 11 (0x800): proxy detected
    // bit 12 (0x1000): zygisk detected (6.2.0-Beta)
    // bit 13 (0x2000): anonymous executable memory with ELF header
    // bit 14 (0x4000): Zygisk companion FD inherited from zygote
    int mask = 0;

    if (aran_is_rooted_artifacts() || aran_check_build_tags(env))
        mask |= 0x001;
    if (isFridaDetected())
        mask |= 0x002;
    if (isDebuggerAttached(env))
        mask |= 0x004;
    if (aran_detect_emulator(env))
        mask |= 0x008;
    if (aran_detect_hooks())
        mask |= 0x010;
    if (!aran_verify_signature(env, expectedSignatureSha256))
        mask |= 0x020;
    if (aran_check_untrusted_installer(env))
        mask |= 0x040;
    if (aran_check_developer_mode(env))
        mask |= 0x080;
    if (aran_check_adb_enabled(env))
        mask |= 0x100;
    if (aran_check_env_tampering())
        mask |= 0x200;
    if (aran_check_runtime_integrity())
        mask |= 0x400;
    if (aran_check_proxy(env))
        mask |= 0x800;

    if (aran_detect_zygisk())
        mask |= 0x1000;
    if (aran_scan_anon_elf())
        mask |= 0x2000;
    if (aran_detect_zygisk_fd())
        mask |= 0x4000;

    return static_cast<jint>(mask);
}

// ════════════════════════════════════════════════════════════════════
// CORDOVA PLUGIN INTERFACE
// ════════════════════════════════════════════════════════════════════

static bool g_initialized = false;

extern "C" JNIEXPORT jint JNICALL
Java_org_mazhai_aran_core_AranNative_runAudit(JNIEnv* env, jclass clazz, jint selector) {
    (void) clazz;
    
    // Map Cordova plugin selectors to security checks
    // SELECTORS from plugin: INTEGRITY_CHECK: 0x1A2B, DEBUG_CHECK: 0x2B3C, etc.
    switch (selector) {
        case 0x1A2B: // INTEGRITY_CHECK
            return Java_org_mazhai_aran_core_AranNative_checkIntegrityNative(env, nullptr, nullptr);
        case 0x2B3C: // DEBUG_CHECK
            return isDebuggerAttached(env) ? 1 : 0;
        case 0x3C4D: // ROOT_CHECK
            return (aran_is_rooted_artifacts() || aran_check_build_tags(env)) ? 1 : 0;
        case 0x4D5E: // JAILBREAK_CHECK (same as root on Android)
            return (aran_is_rooted_artifacts() || aran_check_build_tags(env)) ? 1 : 0;
        case 0x5E6F: // FRIDA_CHECK
            return isFridaDetected() ? 1 : 0;
        case 0x6F70: // EMULATOR_CHECK
            return aran_detect_emulator(env) ? 1 : 0;
        default:
            return 0; // Unknown selector
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_org_mazhai_aran_core_AranNative_getStatus(JNIEnv* env, jclass clazz, jint statusType) {
    (void) env;
    (void) clazz;
    
    // Status types: 0 = initialized, 1 = ready, etc.
    switch (statusType) {
        case 0: // INITIALIZED
            return g_initialized ? 1 : 0;
        case 1: // READY
            return g_initialized ? 1 : 0;
        default:
            return 0;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_core_AranNative_initialize(JNIEnv* env, jclass clazz) {
    (void) env;
    (void) clazz;
    
    // Initialize RASP engine
    g_initialized = true;
}

extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_core_AranNative_shutdown(JNIEnv* env, jclass clazz) {
    (void) env;
    (void) clazz;
    
    // Shutdown RASP engine
    g_initialized = false;
}
