/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Xamarin/.NET MAUI C# Bindings
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Xamarin.Android, Xamarin.iOS, .NET MAUI
 * Architecture: P/Invoke for iOS (.a) and Android (.so)
 */

using System;
using System.Runtime.InteropServices;
using Foundation;

// ============================================
// OBFUSCATED SELECTORS
// ============================================

/**
 * Obfuscated selector values
 */
public static class RASPSelectors
{
    public const int FullAudit = 0x1A2B;
    public const int RootJailbreakOnly = 0x1A2C;
    public const int DebuggerOnly = 0x1A2D;
    public const int FridaOnly = 0x1A2E;
}

/**
 * Obfuscated status type values
 */
public static class RASPStatusTypes
{
    public const int RootJailbreak = 0x2A2B;
    public const int Debugger = 0x2A2C;
    public const int Frida = 0x2A2D;
}

/**
 * Randomized error codes
 */
public static class RASPErrorCodes
{
    public const int SecurityOK = 0x7F3D;
    public const int Suspicious = 0x7F3C;
    public const int HighlySuspicious = 0x7F3B;
    public const int ConfirmedTamper = 0x7F3A;
}

// ============================================
// PLATFORM-SPECIFIC P/INVOKE DECLARATIONS
// ============================================

/**
 * RASPNative - Platform-specific P/Invoke declarations
 * 
 * This class contains platform-specific P/Invoke declarations
 * that call the unified C++ core engine
 */
#if __IOS__
public static class RASPNative
{
    // iOS: Static library is already loaded, use __Internal
    [DllImport("__Internal")]
    private static extern int rasp_invoke_audit_c(int selector);

    [DllImport("__Internal")]
    private static extern int rasp_get_status_c(int statusType);

    [DllImport("__Internal")]
    private static extern void rasp_initialize_c();

    [DllImport("__Internal")]
    private static extern void rasp_shutdown_c();

    // ============================================
    // PUBLIC API
    // ============================================

    public static int ExecuteAudit(int selector)
    {
        try
        {
            return rasp_invoke_audit_c(selector);
        }
        catch (Exception)
        {
            // Silent failure - return randomized error code
            return RASPErrorCodes.SecurityOK;
        }
    }

    public static int GetStatus(int statusType)
    {
        try
        {
            return rasp_get_status_c(statusType);
        }
        catch (Exception)
        {
            // Silent failure - return 0 (not detected)
            return 0;
        }
    }

    public static void Initialize()
    {
        try
        {
            rasp_initialize_c();
        }
        catch (Exception)
        {
            // Silent failure
        }
    }

    public static void Shutdown()
    {
        try
        {
            rasp_shutdown_c();
        }
        catch (Exception)
        {
            // Silent failure
        }
    }
}

#elif __ANDROID__
public static class RASPNative
{
    // Android: Load .so library
    [DllImport("aran_rasp")]
    private static extern int Java_com_aran_rasp_RASPNativeModule_a1_impl(int selector);

    [DllImport("aran_rasp")]
    private static extern int Java_com_aran_rasp_RASPNativeModule_b2_impl(int statusType);

    [DllImport("aran_rasp")]
    private static extern void Java_com_aran_rasp_RASPNativeModule_d4_impl();

    [DllImport("aran_rasp")]
    private static extern void Java_com_aran_rasp_RASPNativeModule_e5_impl();

    // ============================================
    // PUBLIC API
    // ============================================

    public static int ExecuteAudit(int selector)
    {
        try
        {
            return Java_com_aran_rasp_RASPNativeModule_a1_impl(selector);
        }
        catch (Exception)
        {
            // Silent failure - return randomized error code
            return RASPErrorCodes.SecurityOK;
        }
    }

    public static int GetStatus(int statusType)
    {
        try
        {
            return Java_com_aran_rasp_RASPNativeModule_b2_impl(statusType);
        }
        catch (Exception)
        {
            // Silent failure - return 0 (not detected)
            return 0;
        }
    }

    public static void Initialize()
    {
        try
        {
            Java_com_aran_rasp_RASPNativeModule_d4_impl();
        }
        catch (Exception)
        {
            // Silent failure
        }
    }

    public static void Shutdown()
    {
        try
        {
            Java_com_aran_rasp_RASPNativeModule_e5_impl();
        }
        catch (Exception)
        {
            // Silent failure
        }
    }
}

#else
// Fallback for other platforms
public static class RASPNative
{
    public static int ExecuteAudit(int selector) => RASPErrorCodes.SecurityOK;
    public static int GetStatus(int statusType) => 0;
    public static void Initialize() { }
    public static void Shutdown() { }
}
#endif

// ============================================
// .NET MAUI INTERFACE
// ============================================

/**
 * IRASPNative - .NET MAUI interface
 * 
 * Provides a cross-platform interface for .NET MAUI applications
 */
public interface IRASPNative
{
    int ExecuteAudit(int selector);
    int GetStatus(int statusType);
    void Initialize();
    void Shutdown();
}

// ============================================
// .NET MAUI IMPLEMENTATION
// ============================================

/**
 * RASPNativeMAUI - .NET MAUI implementation
 * 
 * Provides a cross-platform implementation for .NET MAUI applications
 * Uses dependency injection for platform-specific implementations
 */
public class RASPNativeMAUI : IRASPNative
{
    private static RASPNativeMAUI _instance;
    public static RASPNativeMAUI Instance => _instance ??= new RASPNativeMAUI();

    private bool initialized = false;

    private RASPNativeMAUI()
    {
        Initialize();
    }

    public int ExecuteAudit(int selector)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.ExecuteAudit(selector);
    }

    public int GetStatus(int statusType)
    {
        if (!initialized)
        {
            Initialize();
        }

        return RASPNative.GetStatus(statusType);
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
}

// ============================================
// HIGH-LEVEL API
// ============================================

/**
 * RASPService - High-level service for Xamarin/.NET MAUI
 * 
 * Provides a clean, type-safe API for Xamarin/.NET MAUI developers
 * Internally uses platform-specific P/Invoke bindings
 */
public class RASPService
{
    private static RASPService _instance;
    public static RASPService Instance => _instance ??= new RASPService();

    private bool initialized = false;

    private RASPService()
    {
        Initialize();
    }

    /**
     * Initialize RASP service
     */
    public void Initialize()
    {
        if (initialized) return;

        RASPNative.Initialize();
        initialized = true;
    }

    /**
     * Shutdown RASP service
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
public class RASPStatus
{
    public bool RootJailbreakDetected { get; set; }
    public bool DebuggerDetected { get; set; }
    public bool FridaDetected { get; set; }
    public int SecurityResult { get; set; }

    public override string ToString()
    {
        return $"RASPStatus{{Root={RootJailbreakDetected}, Debugger={DebuggerDetected}, Frida={FridaDetected}, Result=0x{SecurityResult:X}}}";
    }
}

// ============================================
// USAGE IN XAMARIN
// ============================================

/**
 * Xamarin usage:
 * 
 * ```csharp
 * using System;
 * 
 * public class MainActivity : global::Xamarin.Forms.Platform.Android.FormsAppCompatActivity
 * {
 *     protected override void OnCreate(Bundle savedInstanceState)
 *     {
 *         base.OnCreate(savedInstanceState);
 *         
 *         // Initialize RASP Service
 *         RASPService.Instance.Initialize();
 *         
 *         // Check security
 *         int result = RASPService.Instance.CheckSecurity();
 *         Console.WriteLine($"Security result: 0x{result:X}");
 *         
 *         // Check for root/jailbreak
 *         bool isRooted = RASPService.Instance.IsRootJailbroken();
 *         if (isRooted)
 *         {
 *             Console.WriteLine("Root/Jailbreak detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for debugger
 *         bool isDebuggerAttached = RASPService.Instance.IsDebuggerAttached();
 *         if (isDebuggerAttached)
 *         {
 *             Console.WriteLine("Debugger detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for Frida
 *         bool isFridaAttached = RASPService.Instance.IsFridaAttached();
 *         if (isFridaAttached)
 *         {
 *             Console.WriteLine("Frida detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Get detailed status
 *         RASPStatus status = RASPService.Instance.GetDetailedStatus();
 *         Console.WriteLine($"Detailed status: {status}");
 *     }
 *     
 *     protected override void OnDestroy()
 *     {
 *         base.OnDestroy();
 *         
 *         // Shutdown RASP Service
 *         RASPService.Instance.Shutdown();
 *     }
 * }
 * ```
 */

// ============================================
// USAGE IN .NET MAUI
// ============================================

/**
 * .NET MAUI usage:
 * 
 * ```csharp
 * using Microsoft.Maui;
 * 
 * public class MainPage : ContentPage
 * {
 *     public MainPage()
 *     {
 *         InitializeComponent();
 *         
 *         // Initialize RASP Service
 *         RASPService.Instance.Initialize();
 *         
 *         // Check security
 *         int result = RASPService.Instance.CheckSecurity();
 *         Console.WriteLine($"Security result: 0x{result:X}");
 *         
 *         // Check for root/jailbreak
 *         bool isRooted = RASPService.Instance.IsRootJailbroken();
 *         if (isRooted)
 *         {
 *             Console.WriteLine("Root/Jailbreak detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for debugger
 *         bool isDebuggerAttached = RASPService.Instance.IsDebuggerAttached();
 *         if (isDebuggerAttached)
 *         {
 *             Console.WriteLine("Debugger detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Check for Frida
 *         bool isFridaAttached = RASPService.Instance.IsFridaAttached();
 *         if (isFridaAttached)
 *         {
 *             Console.WriteLine("Frida detected!");
 *             // Take appropriate action
 *         }
 *         
 *         // Get detailed status
 *         RASPStatus status = RASPService.Instance.GetDetailedStatus();
 *         Console.WriteLine($"Detailed status: {status}");
 *     }
 *     
 *     protected override void OnDisappearing()
 *     {
 *         base.OnDisappearing();
 *         
 *         // Shutdown RASP Service
 *         RASPService.Instance.Shutdown();
 *     }
 * }
 * ```
 * 
 * Or use dependency injection:
 * 
 * ```csharp
 * // In MauiProgram.cs
 * builder.Services.AddSingleton<IRASPNative, RASPNativeMAUI>();
 * 
 * // In your page or view model
 * public class MyViewModel
 * {
 *     private readonly IRASPNative _raspNative;
 *     
 *     public MyViewModel(IRASPNative raspNative)
 *     {
 *         _raspNative = raspNative;
 *         
 *         // Initialize
 *         _raspNative.Initialize();
 *         
 *         // Check security
 *         int result = _raspNative.ExecuteAudit(RASPSelectors.FullAudit);
 *     }
 * }
 * ```
 */
