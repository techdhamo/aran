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

// ============================================
// OBFUSCATED SELECTORS
// ============================================

/**
 * Obfuscated selector values
 */
class RASPSelectors {
    static final int FULL_AUDIT = 0x1A2B;
    static final int ROOT_JAILBREAK_ONLY = 0x1A2C;
    static final int DEBUGGER_ONLY = 0x1A2D;
    static final int FRIDA_ONLY = 0x1A2E;
}

/**
 * Obfuscated status type values
 */
class RASPStatusTypes {
    static final int ROOT_JAILBREAK = 0x2A2B;
    static final int DEBUGGER = 0x2A2C;
    static final int FRIDA = 0x2A2D;
}

/**
 * Randomized error codes
 */
class RASPErrorCodes {
    static final int SECURITY_OK = 0x7F3D;
    static final int SUSPICIOUS = 0x7F3C;
    static final int HIGHLY_SUSPICIOUS = 0x7F3B;
    static final int CONFIRMED_TAMPER = 0x7F3A;
}

// ============================================
// CORDOVA PLUGIN
// ============================================

/**
 * RASPCordovaPlugin - Cordova Plugin
 * 
 * Provides a bridge between JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
public class RASPCordovaPlugin extends CordovaPlugin {
    
    static {
        System.loadLibrary("aran_rasp");
    }
    
    // Obfuscated native method names
    private native int a1_impl(int selector);
    private native int b2_impl(int statusType);
    private native void d4_impl();
    private native void e5_impl();
    
    /**
     * Execute action
     * 
     * @param action Obfuscated action name
     * @param args Arguments
     * @param callbackContext Callback context
     */
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
            // Silent failure - return randomized error code
            callbackContext.error(RASPErrorCodes.SECURITY_OK);
            return false;
        }
    }
}

// ============================================
// CAPACITOR PLUGIN
// ============================================

/**
 * RASPCapacitorPlugin - Capacitor Plugin
 * 
 * Provides a bridge between JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "RASPCapacitor")
public class RASPCapacitorPlugin extends Plugin {
    
    static {
        System.loadLibrary("aran_rasp");
    }
    
    // Obfuscated native method names
    private native int a1_impl(int selector);
    private native int b2_impl(int statusType);
    private native void d4_impl();
    private native void e5_impl();
    
    /**
     * Execute security audit
     */
    @PluginMethod
    public void executeAudit(PluginCall call) {
        try {
            int selector = call.getInt("selector", RASPSelectors.FULL_AUDIT);
            int result = a1_impl(selector);
            JSObject ret = new JSObject();
            ret.put("result", result);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("result", RASPErrorCodes.SECURITY_OK);
            call.resolve(ret);
        }
    }
    
    /**
     * Get detection status
     */
    @PluginMethod
    public void getStatus(PluginCall call) {
        try {
            int statusType = call.getInt("statusType", RASPStatusTypes.ROOT_JAILBREAK);
            int status = b2_impl(statusType);
            JSObject ret = new JSObject();
            ret.put("status", status);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("status", 0);
            call.resolve(ret);
        }
    }
    
    /**
     * Check security
     */
    @PluginMethod
    public void checkSecurity(PluginCall call) {
        try {
            int result = a1_impl(RASPSelectors.FULL_AUDIT);
            JSObject ret = new JSObject();
            ret.put("result", result);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("result", RASPErrorCodes.SECURITY_OK);
            call.resolve(ret);
        }
    }
    
    /**
     * Check if root/jailbroken
     */
    @PluginMethod
    public void isRootJailbroken(PluginCall call) {
        try {
            int status = b2_impl(RASPStatusTypes.ROOT_JAILBREAK);
            JSObject ret = new JSObject();
            ret.put("detected", status == 1);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("detected", false);
            call.resolve(ret);
        }
    }
    
    /**
     * Check if debugger attached
     */
    @PluginMethod
    public void isDebuggerAttached(PluginCall call) {
        try {
            int status = b2_impl(RASPStatusTypes.DEBUGGER);
            JSObject ret = new JSObject();
            ret.put("detected", status == 1);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("detected", false);
            call.resolve(ret);
        }
    }
    
    /**
     * Check if Frida attached
     */
    @PluginMethod
    public void isFridaAttached(PluginCall call) {
        try {
            int status = b2_impl(RASPStatusTypes.FRIDA);
            JSObject ret = new JSObject();
            ret.put("detected", status == 1);
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("detected", false);
            call.resolve(ret);
        }
    }
    
    /**
     * Get detailed status
     */
    @PluginMethod
    public void getDetailedStatus(PluginCall call) {
        try {
            JSObject ret = new JSObject();
            ret.put("rootJailbreakDetected", b2_impl(RASPStatusTypes.ROOT_JAILBREAK) == 1);
            ret.put("debuggerDetected", b2_impl(RASPStatusTypes.DEBUGGER) == 1);
            ret.put("fridaDetected", b2_impl(RASPStatusTypes.FRIDA) == 1);
            ret.put("securityResult", a1_impl(RASPSelectors.FULL_AUDIT));
            call.resolve(ret);
        } catch (Exception e) {
            // Silent failure
            JSObject ret = new JSObject();
            ret.put("rootJailbreakDetected", false);
            ret.put("debuggerDetected", false);
            ret.put("fridaDetected", false);
            ret.put("securityResult", RASPErrorCodes.SECURITY_OK);
            call.resolve(ret);
        }
    }
    
    /**
     * Initialize RASP engine
     */
    @PluginMethod
    public void initialize(PluginCall call) {
        try {
            d4_impl();
            call.resolve();
        } catch (Exception e) {
            // Silent failure
            call.resolve();
        }
    }
    
    /**
     * Shutdown RASP engine
     */
    @PluginMethod
    public void shutdown(PluginCall call) {
        try {
            e5_impl();
            call.resolve();
        } catch (Exception e) {
            // Silent failure
            call.resolve();
        }
    }
}

// ============================================
// USAGE IN CORDOVA (JavaScript)
// ============================================

/**
 * Cordova JavaScript usage:
 * 
 * ```javascript
 * // Execute security audit
 * RASPCordovaPlugin.executeAudit(0x1A2B, (result) => {
 *     console.log('Security result:', result);
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * 
 * // Check security
 * RASPCordovaPlugin.checkSecurity((result) => {
 *     console.log('Security result:', result);
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * 
 * // Check if root/jailbroken
 * RASPCordovaPlugin.isRootJailbroken((detected) => {
 *     if (detected) {
 *         console.warn('Root/Jailbreak detected!');
 *     }
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * 
 * // Check if debugger attached
 * RASPCordovaPlugin.isDebuggerAttached((detected) => {
 *     if (detected) {
 *         console.warn('Debugger detected!');
 *     }
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * 
 * // Check if Frida attached
 * RASPCordovaPlugin.isFridaAttached((detected) => {
 *     if (detected) {
 *         console.warn('Frida detected!');
 *     }
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * 
 * // Get detailed status
 * RASPCordovaPlugin.getDetailedStatus((status) => {
 *     console.log('Detailed status:', status);
 * }, (error) => {
 *     console.error('Error:', error);
 * });
 * ```
 */

// ============================================
// USAGE IN CAPACITOR (TypeScript)
// ============================================

/**
 * Capacitor TypeScript usage:
 * 
 * ```typescript
 * import { Plugins } from '@capacitor/core';
 * const { RASPCapacitor } = Plugins;
 * 
 * // Execute security audit
 * const { result } = await RASPCapacitor.executeAudit({ selector: 0x1A2B });
 * console.log('Security result:', result);
 * 
 * // Check security
 * const { result: securityResult } = await RASPCapacitor.checkSecurity();
 * console.log('Security result:', securityResult);
 * 
 * // Check if root/jailbroken
 * const { detected } = await RASPCapacitor.isRootJailbroken();
 * if (detected) {
 *     console.warn('Root/Jailbreak detected!');
 * }
 * 
 * // Check if debugger attached
 * const { detected: debuggerDetected } = await RASPCapacitor.isDebuggerAttached();
 * if (debuggerDetected) {
 *     console.warn('Debugger detected!');
 * }
 * 
 * // Check if Frida attached
 * const { detected: fridaDetected } = await RASPCapacitor.isFridaAttached();
 * if (fridaDetected) {
 *     console.warn('Frida detected!');
 * }
 * 
 * // Get detailed status
 * const status = await RASPCapacitor.getDetailedStatus();
 * console.log('Detailed status:', status);
 * ```
 */

// ============================================
// IOS CAPACITOR PLUGIN (Objective-C++)
// ============================================

/**
 * iOS Capacitor Plugin (Objective-C++)
 * 
 * ```objective-c
 * #import <Capacitor/Capacitor.h>
 * 
 * CAP_PLUGIN(RASPCapacitorPlugin)
 * CAP_PLUGIN_METHOD(executeAudit, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(getStatus, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(checkSecurity, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(isRootJailbroken, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(isDebuggerAttached, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(isFridaAttached, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(getDetailedStatus, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(initialize, CAPPluginReturnPromise);
 * CAP_PLUGIN_METHOD(shutdown, CAPPluginReturnPromise);
 * CAP_PLUGIN_END()
 * 
 * @implementation RASPCapacitorPlugin
 * 
 * - (void)executeAudit:(CAPPluginCall *)call {
 *     int selector = [call getInt:@"selector" default:0x1A2B];
 *     int result = [RASPCore invokeAudit:selector];
 *     [call resolve:@{@"result": @(result)}];
 * }
 * 
 * - (void)getStatus:(CAPPluginCall *)call {
 *     int statusType = [call getInt:@"statusType" default:0x2A2B];
 *     int status = [RASPCore getStatus:statusType];
 *     [call resolve:@{@"status": @(status)}];
 * }
 * 
 * // ... other methods similar to Android implementation
 * 
 * @end
 * ```
 */
