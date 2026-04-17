/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Flutter FFI Wrapper (Enhanced)
 * 
 * This is an enhanced Flutter FFI wrapper that directly calls the C++ engine
 * bypassing the platform's message-passing system for maximum security.
 * 
 * Security Benefits of FFI over MethodChannel:
 * - No "MethodChannel" strings that can be logged
 * - Harder to hook with Frida (raw memory address calls)
 * - No message-passing overhead
 * - Direct Dart VM to Native memory calls
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * - Direct memory access to C++ engine
 */

import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:flutter/foundation.dart';

class RASPSelectors {
  static const int fullAudit = 0x1A2B;
  static const int rootJailbreakOnly = 0x1A2C;
  static const int debuggerOnly = 0x1A2D;
  static const int fridaOnly = 0x1A2E;
}

class RASPStatusTypes {
  static const int rootJailbreak = 0x2A2B;
  static const int debugger = 0x2A2C;
  static const int frida = 0x2A2D;
}

class RASPErrorCodes {
  static const int securityOK = 0x7F3D;
  static const int suspicious = 0x7F3C;
  static const int highlySuspicious = 0x7F3B;
  static const int confirmedTamper = 0x7F3A;
}

typedef ExecuteAuditFunc = ffi.Int32 Function(ffi.Int32);
typedef GetStatusFunc = ffi.Int32 Function(ffi.Int32);
typedef InitializeFunc = ffi.Void Function();
typedef ShutdownFunc = ffi.Void Function();

class RASPNativeLibrary {
  static RASPNativeLibrary? _instance;
  
  ffi.DynamicLibrary? _lib;
  ExecuteAuditFunc? _executeAuditFunc;
  GetStatusFunc? _getStatusFunc;
  InitializeFunc? _initializeFunc;
  ShutdownFunc? _shutdownFunc;
  
  bool _initialized = false;
  
  RASPNativeLibrary._();
  
  factory RASPNativeLibrary() {
    _instance ??= RASPNativeLibrary._();
    return _instance!;
  }
  
  Future<void> initialize() async {
    if (_initialized) return;
    
    try {
      if (Platform.isAndroid) {
        _lib = ffi.DynamicLibrary.open('libaran_rasp.so');
      } else if (Platform.isIOS) {
        _lib = ffi.DynamicLibrary.process();
      } else {
        throw UnsupportedError('Unsupported platform');
      }
      
      _executeAuditFunc = _lib!.lookup<ffi.NativeFunction<ExecuteAuditFunc>>('universal_rasp_execute_audit').asFunction();
      _getStatusFunc = _lib!.lookup<ffi.NativeFunction<GetStatusFunc>>('universal_rasp_get_status').asFunction();
      _initializeFunc = _lib!.lookup<ffi.NativeFunction<InitializeFunc>>('universal_rasp_initialize').asFunction();
      _shutdownFunc = _lib!.lookup<ffi.NativeFunction<ShutdownFunc>>('universal_rasp_shutdown').asFunction();
      
      _initializeFunc!();
      
      _initialized = true;
    } catch (e) {
      debugPrint('RASP FFI initialization failed: $e');
    }
  }
  
  void shutdown() {
    if (!_initialized) return;
    
    try {
      _shutdownFunc?.call();
      _initialized = false;
    } catch (e) {
    }
  }
  
  int executeAudit(int selector) {
    if (!_initialized || _executeAuditFunc == null) {
      return RASPErrorCodes.securityOK;
    }
    
    try {
      return _executeAuditFunc!(selector);
    } catch (e) {
      return RASPErrorCodes.securityOK;
    }
  }
  
  int getStatus(int statusType) {
    if (!_initialized || _getStatusFunc == null) {
      return 0;
    }
    
    try {
      return _getStatusFunc!(statusType);
    } catch (e) {
      return 0;
    }
  }
  
  bool get initialized => _initialized;
}

class RASPFFI {
  static final RASPNativeLibrary _nativeLib = RASPNativeLibrary();
  
  static Future<void> initialize() async {
    await _nativeLib.initialize();
  }
  
  static void shutdown() {
    _nativeLib.shutdown();
  }
  
  static int executeAudit({int selector = RASPSelectors.fullAudit}) {
    if (!_nativeLib.initialized) {
      _nativeLib.initialize().catchError((_) {});
    }
    
    return _nativeLib.executeAudit(selector);
  }
  
  static int getStatus({int statusType = RASPStatusTypes.rootJailbreak}) {
    if (!_nativeLib.initialized) {
      _nativeLib.initialize().catchError((_) {});
    }
    
    return _nativeLib.getStatus(statusType);
  }
  
  static int checkSecurity() {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  static bool isRootJailbroken() {
    return getStatus(statusType: RASPStatusTypes.rootJailbreak) == 1;
  }
  
  static bool isDebuggerAttached() {
    return getStatus(statusType: RASPStatusTypes.debugger) == 1;
  }
  
  static bool isFridaAttached() {
    return getStatus(statusType: RASPStatusTypes.frida) == 1;
  }
  
  static Map<String, dynamic> getDetailedStatus() {
    return {
      'rootJailbreakDetected': isRootJailbroken(),
      'debuggerDetected': isDebuggerAttached(),
      'fridaDetected': isFridaAttached(),
      'securityResult': checkSecurity(),
    };
  }
}

class RASPAsync {
  static final RASPNativeLibrary _nativeLib = RASPNativeLibrary();
  
  static Future<void> initialize() async {
    await _nativeLib.initialize();
  }
  
  static Future<void> shutdown() async {
    _nativeLib.shutdown();
  }
  
  static Future<int> executeAudit({int selector = RASPSelectors.fullAudit}) async {
    if (!_nativeLib.initialized) {
      await _nativeLib.initialize();
    }
    
    return Future.value(_nativeLib.executeAudit(selector));
  }
  
  static Future<int> getStatus({int statusType = RASPStatusTypes.rootJailbreak}) async {
    if (!_nativeLib.initialized) {
      await _nativeLib.initialize();
    }
    
    return Future.value(_nativeLib.getStatus(statusType));
  }
  
  static Future<int> checkSecurity() async {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  static Future<bool> isRootJailbroken() async {
    final int result = await getStatus(statusType: RASPStatusTypes.rootJailbreak);
    return result == 1;
  }
  
  static Future<bool> isDebuggerAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.debugger);
    return result == 1;
  }
  
  static Future<bool> isFridaAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.frida);
    return result == 1;
  }
  
  static Future<Map<String, dynamic>> getDetailedStatus() async {
    return Future.value({
      'rootJailbreakDetected': await isRootJailbroken(),
      'debuggerDetected': await isDebuggerAttached(),
      'fridaDetected': await isFridaAttached(),
      'securityResult': await checkSecurity(),
    });
  }
}
