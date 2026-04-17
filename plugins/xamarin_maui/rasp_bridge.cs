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
 * Architecture: P/Invoke for iOS (libaran_rasp.a) and Android (libaran_rasp.so)
 * Dynamic Library Integration: Uses pre-built native libraries
 */

using System;
using System.Runtime.InteropServices;
using Foundation;

public static class RASPSelectors
{
    public const int FullAudit = 0x1A2B;
    public const int RootJailbreakOnly = 0x1A2C;
    public const int DebuggerOnly = 0x1A2D;
    public const int FridaOnly = 0x1A2E;
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

#if __IOS__
public static class RASPNative
{
    // iOS: Load static library symbols
    [DllImport("__Internal")]
    private static extern int aran_audit_internal(int selector);

    [DllImport("__Internal")]
    private static extern int aran_get_status_internal(int statusType);

    [DllImport("__Internal")]
    private static extern void aran_initialize_internal();

    [DllImport("__Internal")]
    private static extern void aran_shutdown_internal();

    public static int ExecuteAudit(int selector)
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_audit_internal(selector);
        }
        catch (Exception)
        {
            return RASPErrorCodes.SecurityOK;
        }
    }

    public static int GetStatus(int statusType)
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_get_status_internal(statusType);
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public static void Initialize()
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            aran_initialize_internal();
        }
        catch (Exception)
        {
        }
    }

    public static void Shutdown()
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            aran_shutdown_internal();
        }
        catch (Exception)
        {
        }
    }
}

#elif __ANDROID__
public static class RASPNative
{
    // Android: Load shared library (.so)
    [DllImport("libARANRasp")]
    private static extern int aran_audit_internal(int selector);

    [DllImport("libARANRasp")]
    private static extern int aran_get_status_internal(int statusType);

    [DllImport("libARANRasp")]
    private static extern void aran_initialize_internal();

    [DllImport("libARANRasp")]
    private static extern void aran_shutdown_internal();

    public static int ExecuteAudit(int selector)
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_audit_internal(selector);
        }
        catch (Exception)
        {
            return RASPErrorCodes.SecurityOK;
        }
    }

    public static int GetStatus(int statusType)
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            return aran_get_status_internal(statusType);
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public static void Initialize()
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            aran_initialize_internal();
        }
        catch (Exception)
        {
        }
    }

    public static void Shutdown()
    {
        try
        {
            // "Dumb" passthrough - the actual logic is in the native core
            aran_shutdown_internal();
        }
        catch (Exception)
        {
        }
    }
}

#else
public static class RASPNative
{
    public static int ExecuteAudit(int selector) => RASPErrorCodes.SecurityOK;
    public static int GetStatus(int statusType) => 0;
    public static void Initialize() { }
    public static void Shutdown() { }
}
#endif

public class RASPNativeMAUI
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

public class RASPService
{
    private static RASPService _instance;
    public static RASPService Instance => _instance ??= new RASPService();

    private bool initialized = false;

    private RASPService()
    {
        Initialize();
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

    public int ExecuteAudit(int selector = RASPSelectors.FullAudit)
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
