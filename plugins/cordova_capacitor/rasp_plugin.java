/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Cordova/Capacitor Plugin
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Cordova (Java), Capacitor (Java/Obj-C)
 * Architecture: Cordova Plugin, Capacitor Plugin
 */

package com.aran.rasp;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

class RASPSelectors {
    static final int FULL_AUDIT = 0x1A2B;
    static final int ROOT_JAILBREAK_ONLY = 0x1A2C;
    static final int DEBUGGER_ONLY = 0x1A2D;
    static final int FRIDA_ONLY = 0x1A2E;
}

class RASPStatusTypes {
    static final int ROOT_JAILBREAK = 0x2A2B;
    static final int DEBUGGER = 0x2A2C;
    static final int FRIDA = 0x2A2D;
}

class RASPErrorCodes {
    static final int SECURITY_OK = 0x7F3D;
    static final int SUSPICIOUS = 0x7F3C;
    static final int HIGHLY_SUSPICIOUS = 0x7F3B;
    static final int CONFIRMED_TAMPER = 0x7F3A;
}

public class RASPCordovaPlugin extends CordovaPlugin {
    
    static {
        System.loadLibrary("aran_rasp");
    }
    
    private native int a1_impl(int selector);
    private native int b2_impl(int statusType);
    private native void d4_impl();
    private native void e5_impl();
    
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        try {
            switch (action) {
                case "executeAudit":
                    int selector = args.optInt(0, RASPSelectors.FULL_AUDIT);
                    int result = a1_impl(selector);
                    callbackContext.success(result);
                    return true;
                    
                case "getStatus":
                    int statusType = args.optInt(0, RASPStatusTypes.ROOT_JAILBREAK);
                    int status = b2_impl(statusType);
                    callbackContext.success(status);
                    return true;
                    
                case "checkSecurity":
                    int securityResult = a1_impl(RASPSelectors.FULL_AUDIT);
                    callbackContext.success(securityResult);
                    return true;
                    
                case "isRootJailbroken":
                    int rootStatus = b2_impl(RASPStatusTypes.ROOT_JAILBREAK);
                    callbackContext.success(rootStatus == 1);
                    return true;
                    
                case "isDebuggerAttached":
                    int debuggerStatus = b2_impl(RASPStatusTypes.DEBUGGER);
                    callbackContext.success(debuggerStatus == 1);
                    return true;
                    
                case "isFridaAttached":
                    int fridaStatus = b2_impl(RASPStatusTypes.FRIDA);
                    callbackContext.success(fridaStatus == 1);
                    return true;
                    
                case "getDetailedStatus":
                    JSONObject status = new JSONObject();
                    status.put("rootJailbreakDetected", b2_impl(RASPStatusTypes.ROOT_JAILBREAK) == 1);
                    status.put("debuggerDetected", b2_impl(RASPStatusTypes.DEBUGGER) == 1);
                    status.put("fridaDetected", b2_impl(RASPStatusTypes.FRIDA) == 1);
                    status.put("securityResult", a1_impl(RASPSelectors.FULL_AUDIT));
                    callbackContext.success(status);
                    return true;
                    
                case "initialize":
                    d4_impl();
                    callbackContext.success();
                    return true;
                    
                case "shutdown":
                    e5_impl();
                    callbackContext.success();
                    return true;
                    
                default:
                    callbackContext.error("Invalid action");
                    return false;
            }
        } catch (Exception e) {
            callbackContext.error(RASPErrorCodes.SECURITY_OK);
            return false;
        }
    }
}
