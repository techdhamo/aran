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
 * Architecture: P/Invoke for iOS (.a) and Android (.so)
 */

using System;
using System.Runtime.InteropServices;
using UnityEngine;

// ============================================
// OBFUSCATED SELECTORS
// ============================================

/**
 * Obfuscated selector values
 * These hex values map to different security checks in the native engine
 */
public static class RASPSelectors
{
    public const int FullAudit = 0x1A2B; // Full security audit
    public const int RootJailbreakOnly = 0x1A2C; // Root/Jailbreak only
    public const int DebuggerOnly = 0x1A2D; // Debugger only
    public const int FridaOnly = 0x1A2E; // Frida only
}

/**
 * Obfuscated status type values
 */
public static class RASPStatusTypes
{
    public const int RootJailbreak = 0x2A2B; // Root/Jailbreak status
    public const int Debugger = 0x2A2C; // Debugger status
    public const int Frida = 0x2A2D; // Frida status
}

/**
 * Randomized error codes
 */
public static class RASPErrorCodes
{
    public const int SecurityOK = 0x7F3D; // Randomized code for SECURITY_OK
    public const int Suspicious = 0x7F3C; // Randomized code for SUSPICIOUS
    public const int HighlySuspicious = 0x7F3B; // Randomized code for HIGHLY_SUSPICIOUS
    public const int ConfirmedTamper = 0x7F3A; // Randomized code for CONFIRMED_TAMPER
}

// ============================================
// NATIVE P/INVOKE DECLARATIONS
// ============================================

/**
 * RASPNative - P/Invoke declarations for iOS and Android
 * 
 * This class contains platform-specific P/Invoke declarations
 * that call the unified C++ core engine
 */
public static class RASPNative
{
#if UNITY_IOS
    // iOS: Static library is already loaded, use __Internal
    [DllImport("__Internal")]
    private static extern int rasp_invoke_audit_c(int selector);

    [DllImport("__Internal")]
    private static extern int rasp_get_status_c(int statusType);

    [DllImport("__Internal")]
    private static extern void rasp_initialize_c();

    [DllImport("__Internal")]
    private static extern void rasp_shutdown_c();

#elif UNITY_ANDROID
    // Android: Load .so library
    [DllImport("aran_rasp")]
    private static extern int Java_com_aran_rasp_RASPNativeModule_a1_impl(int selector);

    [DllImport("aran_rasp")]
    private static extern int Java_com_aran_rasp_RASPNativeModule_b2_impl(int statusType);

    [DllImport("aran_rasp")]
    private static extern void Java_com_aran_rasp_RASPNativeModule_d4_impl();

    [DllImport("aran_rasp")]
    private static extern void Java_com_aran_rasp_RASPNativeModule_e5_impl();

#else
    // Editor/Other platforms: Fallback implementation
    private static int FallbackExecuteAudit(int selector) => RASPErrorCodes.SecurityOK;
    private static int FallbackGetStatus(int statusType) => 0;
    private static void FallbackInitialize() { }
    private static void FallbackShutdown() { }
#endif

    // ============================================
    // PUBLIC API
    // ============================================

    /**
     * Execute security audit
     * 
     * @param selector Obfuscated selector value
     * @return Randomized error code from native engine
     */
    public static int ExecuteAudit(int selector)
    {
        try
        {
#if UNITY_IOS
            return rasp_invoke_audit_c(selector);
#elif UNITY_ANDROID
            return Java_com_aran_rasp_RASPNativeModule_a1_impl(selector);
#else
            return FallbackExecuteAudit(selector);
#endif
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP ExecuteAudit failed: {e.Message}");
            // Silent failure - return randomized error code
            return RASPErrorCodes.SecurityOK;
        }
    }

    /**
     * Get detection status
     * 
     * @param statusType Obfuscated status type value
     * @return Detection status (0 = not detected, 1 = detected)
     */
    public static int GetStatus(int statusType)
    {
        try
        {
#if UNITY_IOS
            return rasp_get_status_c(statusType);
#elif UNITY_ANDROID
            return Java_com_aran_rasp_RASPNativeModule_b2_impl(statusType);
#else
            return FallbackGetStatus(statusType);
#endif
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP GetStatus failed: {e.Message}");
            // Silent failure - return 0 (not detected)
            return 0;
        }
    }

    /**
     * Initialize RASP engine
     */
    public static void Initialize()
    {
        try
        {
#if UNITY_IOS
            rasp_initialize_c();
#elif UNITY_ANDROID
            Java_com_aran_rasp_RASPNativeModule_d4_impl();
#else
            FallbackInitialize();
#endif
            Debug.Log("RASP Engine initialized successfully");
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP Initialize failed: {e.Message}");
            // Silent failure
        }
    }

    /**
     * Shutdown RASP engine
     */
    public static void Shutdown()
    {
        try
        {
#if UNITY_IOS
            rasp_shutdown_c();
#elif UNITY_ANDROID
            Java_com_aran_rasp_RASPNativeModule_e5_impl();
#else
            FallbackShutdown();
#endif
            Debug.Log("RASP Engine shut down successfully");
        }
        catch (Exception e)
        {
            Debug.LogError($"RASP Shutdown failed: {e.Message}");
            // Silent failure
        }
    }
}

// ============================================
// UNITY MANAGER - High-Level API
// ============================================

/**
 * RASPManager - Unity Manager for RASP Engine
 * 
 * Provides a clean Unity-specific API
 * Attach to a GameObject in your scene
 */
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

    /**
     * Initialize RASP engine
     */
    public void Initialize()
    {
        if (initialized) return;

        RASPNative.Initialize();
        initialized = true;
    }

    /**
     * Shutdown RASP engine
     */
    public void Shutdown()
    {
        if (!initialized) return;

        RASPNative.Shutdown();
        initialized = false;
    }

    /**
     * Execute security audit
     * 
     * @param selector Obfuscated selector value (default: FullAudit)
     * @return Randomized error code from native engine
     */
    public int ExecuteAudit(int selector = RASPSelectors.FullAudit)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.ExecuteAudit(selector);
    }

    /**
     * Get detection status
     * 
     * @param statusType Obfuscated status type value
     * @return Detection status (0 = not detected, 1 = detected)
     */
    public int GetStatus(int statusType = RASPStatusTypes.RootJailbreak)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.GetStatus(statusType);
    }

    /**
     * Convenience method for full security check
     */
    public int CheckSecurity()
    {
        return ExecuteAudit(RASPSelectors.FullAudit);
    }

    /**
     * Convenience method for root/jailbreak detection
     */
    public bool IsRootJailbroken()
    {
        return GetStatus(RASPStatusTypes.RootJailbreak) == 1;
    }

    /**
     * Convenience method for debugger detection
     */
    public bool IsDebuggerAttached()
    {
        return GetStatus(RASPStatusTypes.Debugger) == 1;
    }

    /**
     * Convenience method for Frida detection
     */
    public bool IsFridaAttached()
    {
        return GetStatus(RASPStatusTypes.Frida) == 1;
    }

    /**
     * Get detailed security status
     */
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

/**
 * RASPStatus - Security status data structure
 */
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

// ============================================
// USAGE IN UNITY
// ============================================

/**
 * Unity usage:
 * 
 * ```csharp
 * using UnityEngine;
 * 
 * public class SecurityManager : MonoBehaviour
 * {
 *     void Start()
 *     {
 *         // Initialize RASP Manager
 *         RASPManager.Instance.Initialize();
 *         
 *         // Check security
 *         int result = RASPManager.Instance.CheckSecurity();
 *         Debug.Log($"Security result: 0x{result:X}");
 *         
 *         // Check for root/jailbreak
 *         bool isRooted = RASPManager.Instance.IsRootJailbroken();
 *         if (isRooted)
 *         {
 *             Debug.LogWarning("Root/Jailbreak detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for debugger
 *         bool isDebuggerAttached = RASPManager.Instance.IsDebuggerAttached();
 *         if (isDebuggerAttached)
 *         {
 *             Debug.LogWarning("Debugger detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for Frida
 *         bool isFridaAttached = RASPManager.Instance.IsFridaAttached();
 *         if (isFridaAttached)
 *         {
 *             Debug.LogWarning("Frida detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Get detailed status
 *         RASPStatus status = RASPManager.Instance.GetDetailedStatus();
 *         Debug.Log($"Detailed status: {status}");
 *     }
 *     
 *     void OnDestroy()
 *     {
 *         // Shutdown RASP Manager
 *         RASPManager.Instance.Shutdown();
 *     }
 * }
 * ```
 * 
 * Or use the static API directly:
 * 
 * ```csharp
 * // Initialize
 * RASPNative.Initialize();
 * 
 * // Check security
 * int result = RASPNative.ExecuteAudit(RASPSelectors.FullAudit);
 * 
 * // Check for root/jailbreak
 * bool isRooted = RASPNative.GetStatus(RASPStatusTypes.RootJailbreak) == 1;
 * 
 * // Shutdown
 * RASPNative.Shutdown();
 * ```
 */
