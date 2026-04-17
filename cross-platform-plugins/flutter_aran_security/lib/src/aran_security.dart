import 'dart:async';
import 'package:flutter/services.dart';
import 'models/device_status.dart';
import 'models/start_options.dart';
import 'models/sync_status.dart';
import 'models/threat_event.dart';
import 'enums/reaction_policy.dart';

/// Aran Security SDK for Flutter
///
/// Enterprise mobile security with hardware attestation and cloud-managed threat intelligence.
class AranSecurity {
  static const MethodChannel _channel = MethodChannel('flutter_aran_security');
  static const EventChannel _eventChannel = EventChannel('flutter_aran_security/threats');

  static Stream<ThreatEvent>? _threatStream;

  /// Initialize Aran Security SDK
  ///
  /// Must be called before any other methods.
  ///
  /// Example:
  /// ```dart
  /// await AranSecurity.start(
  ///   StartOptions(
  ///     licenseKey: 'YOUR_LICENSE_KEY',
  ///     expectedSignature: 'YOUR_APK_SIGNATURE_SHA256',
  ///     environment: AranEnvironment.release,
  ///   ),
  /// );
  /// ```
  static Future<void> start(StartOptions options) async {
    try {
      await _channel.invokeMethod('start', options.toMap());
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to initialize: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Perform comprehensive security scan
  ///
  /// Returns [DeviceStatus] with all security flags.
  ///
  /// Example:
  /// ```dart
  /// final status = await AranSecurity.checkEnvironment();
  /// if (status.isRooted) {
  ///   print('Device is rooted!');
  /// }
  /// ```
  static Future<DeviceStatus> checkEnvironment() async {
    try {
      final result = await _channel.invokeMethod('checkEnvironment');
      return DeviceStatus.fromMap(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Security scan failed: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Listen for threat detection events
  ///
  /// Returns a stream of [ThreatEvent] objects.
  ///
  /// Example:
  /// ```dart
  /// AranSecurity.threatStream.listen((event) {
  ///   print('Threat detected: ${event.status.threatCount}');
  ///   if (event.reactionPolicy == 'CUSTOM') {
  ///     // Handle custom threat response
  ///   }
  /// });
  /// ```
  static Stream<ThreatEvent> get threatStream {
    _threatStream ??= _eventChannel.receiveBroadcastStream().map((event) {
      final map = Map<String, dynamic>.from(event);
      return ThreatEvent.fromMap(map);
    });
    return _threatStream!;
  }

  /// Handle detected threats with specified policy
  ///
  /// Example:
  /// ```dart
  /// await AranSecurity.handleThreats(status, ReactionPolicy.custom);
  /// ```
  static Future<void> handleThreats(
    DeviceStatus status,
    ReactionPolicy reactionPolicy,
  ) async {
    try {
      await _channel.invokeMethod('handleThreats', {
        'status': status.toMap(),
        'reactionPolicy': reactionPolicy.value,
      });
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Threat handling failed: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Enable screenshot and screen recording prevention
  ///
  /// Example:
  /// ```dart
  /// await AranSecurity.enableSecureWindow();
  /// ```
  static Future<void> enableSecureWindow() async {
    try {
      await _channel.invokeMethod('enableSecureWindow');
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to enable secure window: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Disable screenshot prevention
  ///
  /// Example:
  /// ```dart
  /// await AranSecurity.disableSecureWindow();
  /// ```
  static Future<void> disableSecureWindow() async {
    try {
      await _channel.invokeMethod('disableSecureWindow');
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to disable secure window: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Get cloud sync status
  ///
  /// Returns [SyncStatus] with last sync timestamp and request ID.
  ///
  /// Example:
  /// ```dart
  /// final syncStatus = await AranSecurity.getSyncStatus();
  /// print('Last sync: ${DateTime.fromMillisecondsSinceEpoch(syncStatus.lastSyncTimestamp)}');
  /// ```
  static Future<SyncStatus> getSyncStatus() async {
    try {
      final result = await _channel.invokeMethod('getSyncStatus');
      return SyncStatus.fromMap(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to get sync status: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Get device fingerprint
  ///
  /// Returns unique device fingerprint string.
  ///
  /// Example:
  /// ```dart
  /// final fingerprint = await AranSecurity.getDeviceFingerprint();
  /// ```
  static Future<String> getDeviceFingerprint() async {
    try {
      final result = await _channel.invokeMethod('getDeviceFingerprint');
      return result as String;
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to get device fingerprint: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Clear clipboard (security utility)
  ///
  /// Example:
  /// ```dart
  /// await AranSecurity.clearClipboard();
  /// ```
  static Future<void> clearClipboard() async {
    try {
      await _channel.invokeMethod('clearClipboard');
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to clear clipboard: ${e.message}',
        code: e.code,
      );
    }
  }

  /// Generate Aran Sigil (hardware-attested JWT)
  ///
  /// Returns hardware-attested JWT token.
  ///
  /// Example:
  /// ```dart
  /// final sigil = await AranSecurity.generateSigil();
  /// // Use in API requests
  /// final response = await http.get(
  ///   Uri.parse('https://api.example.com/secure'),
  ///   headers: {'X-Aran-Sigil': sigil},
  /// );
  /// ```
  static Future<String> generateSigil() async {
    try {
      final result = await _channel.invokeMethod('generateSigil');
      return result as String;
    } on PlatformException catch (e) {
      throw AranSecurityException(
        'Failed to generate Sigil: ${e.message}',
        code: e.code,
      );
    }
  }
}

/// Exception thrown by Aran Security SDK
class AranSecurityException implements Exception {
  final String message;
  final String? code;

  AranSecurityException(this.message, {this.code});

  @override
  String toString() => 'AranSecurityException: $message${code != null ? ' (code: $code)' : ''}';
}
