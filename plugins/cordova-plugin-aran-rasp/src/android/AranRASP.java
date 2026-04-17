/**
 * ARAN RASP ENGINE - Cordova Android Plugin (Abstract Architecture)
 * 
 * This is a professional, abstract RASP layer that acts as a "dumb" passthrough
 * to the pre-compiled native cores (AAR).
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - "Dumb" passthrough to pre-compiled native cores
 * 
 * Architecture:
 * - Cordova (JS) -> Native Bridge -> Native Core (AAR)
 * - No logic in plugin - all security logic in native core
 */

package com.aran.rasp;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.json.JSONArray;
import org.json.JSONException;
import org.mazhai.aran.core.AranNative; // Fetched from your .aar

public class AranRASP extends CordovaPlugin {
    
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("execute")) {
            int selector = args.getInt(0);
            // "Dumb" passthrough - the actual logic is in the AAR
            int result = AranNative.runAudit(selector);
            callbackContext.success(result);
            return true;
        } else if (action.equals("getStatus")) {
            int statusType = args.getInt(0);
            // "Dumb" passthrough - the actual logic is in the AAR
            int result = AranNative.getStatus(statusType);
            callbackContext.success(result);
            return true;
        } else if (action.equals("initialize")) {
            // "Dumb" passthrough - the actual logic is in the AAR
            AranNative.initialize();
            callbackContext.success();
            return true;
        } else if (action.equals("shutdown")) {
            // "Dumb" passthrough - the actual logic is in the AAR
            AranNative.shutdown();
            callbackContext.success();
            return true;
        }
        return false;
    }
}
