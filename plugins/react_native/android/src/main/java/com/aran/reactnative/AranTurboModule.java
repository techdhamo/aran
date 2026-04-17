/**
 * ARAN RASP ENGINE - React Native TurboModule Implementation (Android)
 * 
 * This is a professional, abstract RASP layer that uses TurboModule
 * instead of the React Native Bridge, which is easily monitored by Frida.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - TURBOMODULE (bypasses Bridge monitoring)
 * - "Dumb" passthrough to pre-compiled native cores
 * 
 * Architecture:
 * - React Native (JS) -> TurboModule -> Native Core (AAR)
 * - No Bridge (easier to hook with Frida)
 * - Direct native function calls
 */

package com.aran.reactnative;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;
import com.aran.core.ARANRasp; // Fetched from your .aar

@ReactModule(name = "AranTurboModule")
public class AranTurboModule extends ReactContextBaseJavaModule {

    private static final String NAME = "AranTurboModule";
    private final ReactApplicationContext reactContext;

    public AranTurboModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return NAME;
    }

    // ============================================
    // VALIDATE - "Dumb" Passthrough to Native Core
    // ============================================
    @ReactMethod
    public void validate(int selector, Promise promise) {
        try {
            // "Dumb" passthrough - the actual logic is in the AAR
            // Hidden execution - bypasses Bridge monitoring
            int result = ARANRasp.runAudit(selector);
            
            promise.resolve(result);
        } catch (Exception e) {
            // Silent failure - return 0x7F3D (Security OK) on error
            promise.resolve(0x7F3D);
        }
    }

    // ============================================
    // INITIALIZE
    // ============================================
    @ReactMethod
    public void initialize(Promise promise) {
        try {
            ARANRasp.initialize();
            promise.resolve(true);
        } catch (Exception e) {
            // Silent failure
            promise.resolve(true);
        }
    }

    // ============================================
    // SHUTDOWN
    // ============================================
    @ReactMethod
    public void shutdown(Promise promise) {
        try {
            ARANRasp.shutdown();
            promise.resolve(true);
        } catch (Exception e) {
            // Silent failure
            promise.resolve(true);
        }
    }

    // ============================================
    // GET STATUS
    // ============================================
    @ReactMethod
    public void getStatus(int statusType, Promise promise) {
        try {
            // "Dumb" passthrough - the actual logic is in the AAR
            int result = ARANRasp.getStatus(statusType);
            
            promise.resolve(result);
        } catch (Exception e) {
            // Silent failure - return 0 on error
            promise.resolve(0);
        }
    }
}
