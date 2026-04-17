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
import 'dart:io';
import 'package:flutter/services.dart';

// ============================================
// OBFUSCATED SELECTORS
// ============================================

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

// ============================================
// METHOD CHANNEL IMPLEMENTATION
// ============================================

class RASPPlugin {
  static const MethodChannel _channel = MethodChannel('com.aran.secure.bridge');
  
  static final RASPPlugin _instance = RASPPlugin._internal();
  factory RASPPlugin() => _instance;
  RASPPlugin._internal();
  
  Future<int> executeAudit({int selector = RASPSelectors.fullAudit}) async {
    try {
      final int result = await _channel.invokeMethod('executeAudit', {
        'selector': selector,
      });
      return result;
    } on PlatformException catch (_) {
      return RASPErrorCodes.securityOK;
    }
  }
  
  Future<int> getStatus({int statusType = RASPStatusTypes.rootJailbreak}) async {
    try {
      final int result = await _channel.invokeMethod('getStatus', {
        'statusType': statusType,
      });
      return result;
    } on PlatformException catch (_) {
      return 0;
    }
  }
  
  Future<int> checkSecurity() async {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  Future<bool> isRootJailbroken() async {
    final int result = await getStatus(statusType: RASPStatusTypes.rootJailbreak);
    return result == 1;
  }
  
  Future<bool> isDebuggerAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.debugger);
    return result == 1;
  }
  
  Future<bool> isFridaAttached() async {
    final int result = await getStatus(statusType: RASPStatusTypes.frida);
    return result == 1;
  }
  
  Future<Map<String, dynamic>> getDetailedStatus() async {
    try {
      final Map<String, dynamic> result = await _channel.invokeMethod('getDetailedStatus');
      return result;
    } on PlatformException catch (_) {
      return {};
    }
  }
}

// ============================================
// C++ FFI BINDINGS (Alternative Implementation)
// ============================================

class RASPFFI {
  ffi.DynamicLibrary? _lib;
  ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>? _executeAuditFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>? _getStatusFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Void Function()>>? _initializeFunc;
  ffi.Pointer<ffi.NativeFunction<ffi.Void Function()>>? _shutdownFunc;
  
  bool _initialized = false;
  
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
      
      _executeAuditFunc = _lib!.lookup<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>('universal_rasp_execute_audit');
      _getStatusFunc = _lib!.lookup<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>>('universal_rasp_get_status');
      _initializeFunc = _lib!.lookup<ffi.NativeFunction<ffi.Void Function()>>('universal_rasp_initialize');
      _shutdownFunc = _lib!.lookup<ffi.NativeFunction<ffi.Void Function()>>('universal_rasp_shutdown');
      
      _initializeFunc!.asFunction<void Function()>()();
      
      _initialized = true;
    } catch (_) {}
  }
  
  void shutdown() {
    if (!_initialized) return;
    
    try {
      _shutdownFunc?.asFunction<void Function()>()();
      _initialized = false;
    } catch (_) {}
  }
  
  int executeAudit({int selector = RASPSelectors.fullAudit}) {
    if (!_initialized) {
      return RASPErrorCodes.securityOK;
    }
    
    try {
      return _executeAuditFunc!.asFunction<int Function(int)>()(selector);
    } catch (_) {
      return RASPErrorCodes.securityOK;
    }
  }
  
  int getStatus({int statusType = RASPStatusTypes.rootJailbreak}) {
    if (!_initialized) {
      return 0;
    }
    
    try {
      return _getStatusFunc!.asFunction<int Function(int)>()(statusType);
    } catch (_) {
      return 0;
    }
  }
  
  int checkSecurity() {
    return executeAudit(selector: RASPSelectors.fullAudit);
  }
  
  bool isRootJailbroken() {
    return getStatus(statusType: RASPStatusTypes.rootJailbreak) == 1;
  }
  
  bool isDebuggerAttached() {
    return getStatus(statusType: RASPStatusTypes.debugger) == 1;
  }
  
  bool isFridaAttached() {
    return getStatus(statusType: RASPStatusTypes.frida) == 1;
  }
}

// ============================================
// PUBLIC API
// ============================================

class UniversalRASP {
  static final RASPPlugin _methodChannelPlugin = RASPPlugin();
  static final RASPFFI _ffiPlugin = RASPFFI();
  static bool _useFFI = false;
  
  static Future<void> initialize({bool useFFI = false}) async {
    _useFFI = useFFI;
    if (_useFFI) {
      await _ffiPlugin.initialize();
    }
  }
  
  static void shutdown() {
    if (_useFFI) {
      _ffiPlugin.shutdown();
    }
  }
  
  static Future<int> executeAudit({int selector = RASPSelectors.fullAudit}) async {
    if (_useFFI) {
      return Future.value(_ffiPlugin.executeAudit(selector: selector));
    }
    return _methodChannelPlugin.executeAudit(selector: selector);
  }
  
  static Future<int> getStatus({int statusType = RASPStatusTypes.rootJailbreak}) async {
    if (_useFFI) {
      return Future.value(_ffiPlugin.getStatus(statusType: statusType));
    }
    return _methodChannelPlugin.getStatus(statusType: statusType);
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
