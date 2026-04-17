/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Flutter Plugin
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: Android (JNI), iOS (MethodChannel), C++ FFI
 */

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:flutter/services.dart';

// ============================================
// OBFUSCATED SELECTORS
// ============================================

/**
 * Obfuscated selector values
 * These hex values map to different security checks in the native engine
 * Avoid descriptive names like "isRooted" or "detectJailbreak"
 */
class RASPSelectors {
  static const int fullAudit = 0x1A2B; // Full security audit
  static const int rootJailbreakOnly = 0x1A2C; // Root/Jailbreak only
  static const int debuggerOnly = 0x1A2D; // Debugger only
  static const int fridaOnly = 0x1A2E; // Frida only
}

/**
 * Obfuscated status type values
 * These hex values map to different detection status queries
 */
class RASPStatusTypes {
  static const int rootJailbreak = 0x2A2B; // Root/Jailbreak status
  static const int debugger = 0x2A2C; // Debugger status
  static const int frida = 0x2A2D; // Frida status
}

/**
 * Randomized error codes
 * These are returned by the native engine and interpreted by the plugin
 * Avoid descriptive error codes like "SECURITY_OK" or "TAMPER_DETECTED"
 */
class RASPErrorCodes {
  static const int securityOK = 0x7F3D; // Randomized code for SECURITY_OK
  static const int suspicious = 0x7F3C; // Randomized code for SUSPICIOUS
  static const int highlySuspicious = 0x7F3B; // Randomized code for HIGHLY_SUSPICIOUS
  static const int confirmedTamper = 0x7F3A; // Randomized code for CONFIRMED_TAMPER
}

// ============================================
// METHOD CHANNEL IMPLEMENTATION
// ============================================

/**
 * RASP Plugin - MethodChannel Implementation
 * 
 * Uses Flutter's MethodChannel to communicate with native code
 * Channel name is obfuscated to avoid sensitive strings
 */
class RASPPlugin {
  static const MethodChannel _channel = MethodChannel('com.aran.secure.bridge');
  
  static final RASPPlugin _instance = RASPPlugin._internal();
  factory RASPPlugin() => _instance;
  RASPPlugin._internal();
  
  /**
   * Execute security audit
   * 
   * @param selector Obfuscated selector value (default: fullAudit)
   * @return Randomized error code from native engine
   */
  Future<int> executeAudit({int selector = RASPSelectors.fullAudit}) async {
    try {
      final int result = await _channel.invokeMethod('executeAudit', {
        'selector': selector,
      });
      return result;
    } on PlatformException catch (e) {
      // Silent failure - return randomized error code
      return RASPErrorCodes.securityOK;
    }
  }
  
  /**
   * Get detection status
   * 
   * @param statusType Obfuscated status type value
   * @return Detection status (0 = not detected, 1 = detected)
   */
  Future<int> getStatus({int statusType = RASPStatusTypes.rootJailbreak}) async {
    try {
      final int result = await _channel.invokeMethod('getStatus', {
        'statusType': statusType,
      });
      return result;
    } on PlatformException catch (e) {
      // Silent failure - return 0 (not detected)
      return 0;
    }
  }
  
  /**
   * Convenience method for full security check
   * 
   * @return Randomized error code from native engine
   */
  Future<int> checkSecurity() async {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  /**
   * Convenience method for root/jailbreak detection
   * 
   * @return True if root/jailbreak detected
   */
  Future<bool> isRootJailbroken() async {
    final int result = await getStatus(statusType: RASPStatusTypes.rootJailbreak);
    return result == 1;
  }
  
  /**
   * Convenience method for debugger detection
   * 
   * @return True if debugger detected
   */
  Future<bool> isDebuggerAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.debugger);
    return result == 1;
  }
  
  /**
   * Convenience method for Frida detection
   * 
   * @return True if Frida detected
   */
  Future<bool> isFridaAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.frida);
    return result == 1;
  }
  
  /**
   * Get detailed security status
   * 
   * @return Map with all detection statuses
   */
  Future<Map<String, dynamic>> getDetailedStatus() async {
    try {
      final Map<String, dynamic> result = await _channel.invokeMethod('getDetailedStatus');
      return result;
    } on PlatformException catch (e) {
      // Silent failure - return empty map
      return {};
    }
  }
}

// ============================================
// C++ FFI BINDINGS (Alternative Implementation)
// ============================================

/**
 * RASP Plugin - C++ FFI Implementation
 * 
 * This is an alternative implementation that uses Dart FFI to call
 * the C++ functions directly, bypassing Flutter's MethodChannel overhead.
 * 
 * Usage:
 * ```dart
 * final ffiPlugin = RASPFFI();
 * await ffiPlugin.initialize();
 * final result = ffiPlugin.executeAudit(selector: RASPSelectors.fullAudit);
 * ```
 */
class RASPFFI {
  ffi.DynamicLibrary? _lib;
  ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>? _executeAuditFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>? _getStatusFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Void Function()>>? _initializeFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Void Function()>>? _shutdownFunc;
  
  bool _initialized = false;
  
  /**
   * Initialize RASP FFI
   * Loads the native library and resolves function symbols
   */
  Future<void> initialize() async {
    if (_initialized) return;
    
    try {
      // Load the native library
      if (Platform.isAndroid) {
        _lib = ffi.DynamicLibrary.open('libaran_rasp.so');
      } else if (Platform.isIOS) {
        _lib = ffi.DynamicLibrary.process(); // Static library is already loaded
      } else {
        throw UnsupportedError('Unsupported platform');
      }
      
      // Resolve function symbols
      _executeAuditFunc = _lib!.lookup<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>('universal_rasp_execute_audit');
      _getStatusFunc = _lib!.lookup<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>('universal_rasp_get_status');
      _initializeFunc = _lib!.lookup<ffi.NativeFunction<ffi.Void Function()>>('universal_rasp_initialize');
      _shutdownFunc = _lib!.lookup<ffi.NativeFunction<ffi.Void Function()>>('universal_rasp_shutdown');
      
      // Call initialize function
      _initializeFunc!.asFunction<void Function()>()();
      
      _initialized = true;
    } catch (e) {
      // Silent failure - continue with MethodChannel fallback
    }
  }
  
  /**
   * Shutdown RASP FFI
   */
  void shutdown() {
    if (!_initialized) return;
    
    try {
      _shutdownFunc?.asFunction<void Function()>()();
      _initialized = false;
    } catch (e) {
      // Silent failure
    }
  }
  
  /**
   * Execute security audit via FFI
   * 
   * @param selector Obfuscated selector value
   * @return Randomized error code from native engine
   */
  int executeAudit({int selector = RASPSelectors.fullAudit}) {
    if (!_initialized) {
      // Fallback to MethodChannel
      return RASPPlugin().executeAudit(selector: selector).then((value) => value).catchError((_) => RASPErrorCodes.securityOK);
    }
    
    try {
      return _executeAuditFunc!.asFunction<int Function(int)>()(selector);
    } catch (e) {
      // Silent failure - return randomized error code
      return RASPErrorCodes.securityOK;
    }
  }
  
  /**
   * Get detection status via FFI
   * 
   * @param statusType Obfuscated status type value
   * @return Detection status (0 = not detected, 1 = detected)
   */
  int getStatus({int statusType = RASPStatusTypes.rootJailbreak}) {
    if (!_initialized) {
      // Fallback to MethodChannel
      return RASPPlugin().getStatus(statusType: statusType).then((value) => value).catchError((_) => 0);
    }
    
    try {
      return _getStatusFunc!.asFunction<int Function(int)>()(statusType);
    } catch (e) {
      // Silent failure - return 0 (not detected)
      return 0;
    }
  }
  
  /**
   * Convenience method for full security check
   */
  int checkSecurity() {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  /**
   * Convenience method for root/jailbreak detection
   */
  bool isRootJailbroken() {
    return getStatus(statusType: RASPStatusTypes.rootJailbreak) == 1;
  }
  
  /**
   * Convenience method for debugger detection
   */
  bool isDebuggerAttached() {
    return getStatus(statusType: RASPStatusTypes.debugger) == 1;
  }
  
  /**
   * Convenience method for Frida detection
   */
  bool isFridaAttached() {
    return getStatus(statusType: RASPStatusTypes.frida) == 1;
  }
}

// ============================================
// PUBLIC API
// ============================================

/**
 * UniversalRASP - Public API for Flutter applications
 * 
 * Provides a clean, type-safe API for Flutter developers
 * Internally uses either MethodChannel or FFI (whichever is available)
 */
class UniversalRASP {
  static final RASPPlugin _methodChannelPlugin = RASPPlugin();
  static final RASPFFI _ffiPlugin = RASPFFI();
  static bool _useFFI = false;
  
  /**
   * Initialize UniversalRASP
   * 
   * @param useFFI If true, attempts to use FFI (default: false for MethodChannel)
   */
  static Future<void> initialize({bool useFFI = false}) async {
    _useFFI = useFFI;
    if (_useFFI) {
      await _ffiPlugin.initialize();
    }
  }
  
  /**
   * Shutdown UniversalRASP
   */
  static void shutdown() {
    if (_useFFI) {
      _ffiPlugin.shutdown();
    }
  }
  
  /**
   * Execute security audit
   * 
   * @param selector Obfuscated selector value (default: fullAudit)
   * @return Randomized error code from native engine
   */
  static Future<int> executeAudit({int selector = RASPSelectors.fullAudit}) async {
    if (_useFFI) {
      return Future.value(_ffiPlugin.executeAudit(selector: selector));
    }
    return _methodChannelPlugin.executeAudit(selector: selector);
  }
  
  /**
   * Get detection status
   * 
   * @param statusType Obfuscated status type value
   * @return Detection status (0 = not detected, 1 = detected)
   */
  static Future<int> getStatus({int statusType = RASPStatusTypes.rootJailbreak}) async {
    if (_useFFI) {
      return Future.value(_ffiPlugin.getStatus(statusType: statusType));
    }
    return _methodChannelPlugin.getStatus(statusType: statusType);
  }
  
  /**
   * Convenience method for full security check
   */
  static Future<int> checkSecurity() async {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  /**
   * Convenience method for root/jailbreak detection
   */
  static Future<bool> isRootJailbroken() async {
    final int result = await getStatus(statusType: RASPStatusTypes.rootJailbreak);
    return result == 1;
  }
  
  /**
   * Convenience method for debugger detection
   */
  static Future<bool> isDebuggerAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.debugger);
    return result == 1;
  }
  
  /**
   * Convenience method for Frida detection
   */
  static Future<bool> isFridaAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.frida);
    return result == 1;
  }
  
  /**
   * Get detailed security status
   */
  static Future<Map<String, dynamic>> getDetailedStatus() async {
    if (_useFFI) {
      return Future.value({
        'rootJailbreakDetected': _ffiPlugin.isRootJailbroken(),
        'debuggerDetected': _ffiPlugin.isDebuggerAttached(),
        'fridaDetected': _ffiPlugin.isFridaAttached(),
        'securityResult': _ffiPlugin.checkSecurity(),
      });
    }
    return _methodChannelPlugin.getDetailedStatus();
  }
}
