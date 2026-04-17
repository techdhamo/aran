/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Unity C# P/Invoke Bridge
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Unity (C# P/Invoke)
 * Architecture: P/Invoke for iOS (libaran_rasp.a) and Android (libaran_rasp.so)
 * Dynamic Library Integration: Uses pre-built native libraries
 */

using System;
using System.Runtime.InteropServices;
using UnityEngine;

// ============================================
// OBFUSCATED SELECTORS
// ============================================

public static class RASPSelectors
{
    public const int IntegrityCheck = 0x1A2B;
    public const int DebugCheck = 0x2B3C;
    public const int RootCheck = 0x3C4D;
    public const int JailbreakCheck = 0x4D5E;
    public const int FridaCheck = 0x5E6F;
    public const int EmulatorCheck = 0x6F70;
}

public static class RASPStatusTypes
{
    public const int RootJailbreak = 0x2A2B;
    public const int Debugger = 0x2A2C;
    public const int Frida = 0x2A2D;
}

public static class RASPErrorCodes
{
    public const int SecurityOK = 0x7F3D;
    public const int Suspicious = 0x7F3C;
    public const int HighlySuspicious = 0x7F3B;
    public const int ConfirmedTamper = 0x7F3A;
}

// ============================================
// NATIVE P/INVOKE DECLARATIONS
// ============================================

public static class RASPNative
{
#if UNITY_IOS
    // iOS: Load static library symbols
    [DllImport("__Internal")]
    private static extern int aran_audit_internal(int selector);

    [DllImport("__Internal")]
    private static extern int aran_get_status_internal(int statusType);

    [DllImport("__Internal")]
    private static extern void aran_initialize_internal();

    [DllImport("__Internal")]
    private static extern void aran_shutdown_internal();

#elif UNITY_ANDROID
    // Android: Load shared library (.so)
    [DllImport("libARANRasp")]
    private static extern int aran_audit_internal(int selector);

    [DllImport("libARANRasp")]
    private static extern int aran_get_status_internal(int statusType);

    [DllImport("libARANRasp")]
    private static extern void aran_initialize_internal();

    [DllImport("libARANRasp")]
    private static extern void aran_shutdown_internal();

#else
    private static int FallbackExecuteAudit(int selector) => RASPErrorCodes.SecurityOK;
    private static int FallbackGetStatus(int statusType) => 0;
    private static void FallbackInitialize() { }
    private static void FallbackShutdown() { }
#endif

    public static int ExecuteAudit(int selector)
    {
        try
        {
#if UNITY_IOS || UNITY_ANDROID
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_audit_internal(selector);
#else
            return FallbackExecuteAudit(selector);
#endif
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP ExecuteAudit failed: {e.Message}");
            return RASPErrorCodes.SecurityOK;
        }
    }

    public static int GetStatus(int statusType)
    {
        try
        {
#if UNITY_IOS || UNITY_ANDROID
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_get_status_internal(statusType);
#else
            return FallbackGetStatus(statusType);
#endif
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP GetStatus failed: {e.Message}");
            return 0;
        }
    }

    public static void Initialize()
    {
        try
        {
#if UNITY_IOS || UNITY_ANDROID
            // "Dumb" passthrough - the actual logic is in the native core
            aran_initialize_internal();
#else
            FallbackInitialize();
#endif
            Debug.Log("RASP Engine initialized successfully");
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP Initialize failed: {e.Message}");
        }
    }

    public static void Shutdown()
    {
        try
        {
#if UNITY_IOS || UNITY_ANDROID
            // "Dumb" passthrough - the actual logic is in the native core
            aran_shutdown_internal();
#else
            FallbackShutdown();
#endif
            Debug.Log("RASP Engine shut down successfully");
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP Shutdown failed: {e.Message}");
        }
    }
}

// ============================================
// UNITY MANAGER
// ============================================

public class RASPManager : MonoBehaviour
{
    private static RASPManager _instance;
    public static RASPManager Instance => _instance;

    private bool initialized = false;

    void Awake()
    {
        if (_instance == null)
        {
            _instance = this;
            DontDestroyOnLoad(gameObject);
            Initialize();
        }
        else
        {
            Destroy(gameObject);
        }
    }

    void OnDestroy()
    {
        if (_instance == this)
        {
            Shutdown();
        }
    }

    public void Initialize()
    {
        if (initialized) return;

        RASPNative.Initialize();
        initialized = true;
    }

    public void Shutdown()
    {
        if (!initialized) return;

        RASPNative.Shutdown();
        initialized = false;
    }

    public int ExecuteAudit(int selector = RASPSelectors.IntegrityCheck)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.ExecuteAudit(selector);
    }

    public int GetStatus(int statusType = RASPStatusTypes.RootJailbreak)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.GetStatus(statusType);
    }

    public int CheckSecurity()
    {
        return ExecuteAudit(RASPSelectors.FullAudit);
    }

    public bool IsRootJailbroken()
    {
        return GetStatus(RASPStatusTypes.RootJailbreak) == 1;
    }

    public bool IsDebuggerAttached()
    {
        return GetStatus(RASPStatusTypes.Debugger) == 1;
    }

    public bool IsFridaAttached()
    {
        return GetStatus(RASPStatusTypes.Frida) == 1;
    }

    public RASPStatus GetDetailedStatus()
    {
        return new RASPStatus
        {
            RootJailbreakDetected = IsRootJailbroken(),
            DebuggerDetected = IsDebuggerAttached(),
            FridaDetected = IsFridaAttached(),
            SecurityResult = CheckSecurity()
        };
    }
}

// ============================================
// DATA STRUCTURES
// ============================================

[Serializable]
public class RASPStatus
{
    public bool RootJailbreakDetected;
    public bool DebuggerDetected;
    public bool FridaDetected;
    public int SecurityResult;

    public override string ToString()
    {
        return $"RASPStatus{{Root={RootJailbreakDetected}, Debugger={DebuggerDetected}, Frida={FridaDetected}, Result=0x{SecurityResult:X}}}";
    }
}
