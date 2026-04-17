/// Device security status with all threat flags
class DeviceStatus {
  // Native C++ detections
  final bool isRooted;
  final bool fridaDetected;
  final bool debuggerAttached;
  final bool emulatorDetected;
  final bool hooked;
  final bool tampered;
  final bool untrustedInstaller;
  final bool developerMode;
  final bool adbEnabled;
  final bool envTampering;
  final bool runtimeIntegrity;
  final bool proxyDetected;
  final bool zygiskDetected;

  // Kotlin-level / Swift-level detections
  final bool vpnDetected;
  final bool screenRecording;
  final bool keyloggerRisk;
  final bool untrustedKeyboard;
  final bool deviceLockMissing;
  final bool overlayDetected;
  final bool unsecuredWifi;
  final bool timeSpoofing;
  final bool locationSpoofing;
  final bool screenMirroring;

  // Lists
  final List<String> malwarePackages;
  final List<String> smsForwarderApps;
  final List<String> remoteAccessApps;

  // Metadata
  final String deviceFingerprint;
  final String appId;
  final String eventId;
  final int nativeThreatMask;
  final int timestamp;
  final bool hasThreat;
  final int threatCount;

  const DeviceStatus({
    required this.isRooted,
    required this.fridaDetected,
    required this.debuggerAttached,
    required this.emulatorDetected,
    required this.hooked,
    required this.tampered,
    required this.untrustedInstaller,
    required this.developerMode,
    required this.adbEnabled,
    required this.envTampering,
    required this.runtimeIntegrity,
    required this.proxyDetected,
    this.zygiskDetected = false,
    required this.vpnDetected,
    required this.screenRecording,
    required this.keyloggerRisk,
    required this.untrustedKeyboard,
    required this.deviceLockMissing,
    required this.overlayDetected,
    required this.unsecuredWifi,
    this.timeSpoofing = false,
    this.locationSpoofing = false,
    this.screenMirroring = false,
    required this.malwarePackages,
    required this.smsForwarderApps,
    required this.remoteAccessApps,
    required this.deviceFingerprint,
    required this.appId,
    this.eventId = '',
    this.nativeThreatMask = 0,
    this.timestamp = 0,
    required this.hasThreat,
    required this.threatCount,
  });

  factory DeviceStatus.fromMap(Map<String, dynamic> map) {
    return DeviceStatus(
      isRooted: map['isRooted'] as bool,
      fridaDetected: map['fridaDetected'] as bool,
      debuggerAttached: map['debuggerAttached'] as bool,
      emulatorDetected: map['emulatorDetected'] as bool,
      hooked: map['hooked'] as bool,
      tampered: map['tampered'] as bool,
      untrustedInstaller: map['untrustedInstaller'] as bool,
      developerMode: map['developerMode'] as bool,
      adbEnabled: map['adbEnabled'] as bool,
      envTampering: map['envTampering'] as bool,
      runtimeIntegrity: map['runtimeIntegrity'] as bool,
      proxyDetected: map['proxyDetected'] as bool,
      zygiskDetected: (map['zygiskDetected'] as bool?) ?? false,
      vpnDetected: map['vpnDetected'] as bool,
      screenRecording: map['screenRecording'] as bool,
      keyloggerRisk: map['keyloggerRisk'] as bool,
      untrustedKeyboard: map['untrustedKeyboard'] as bool,
      deviceLockMissing: map['deviceLockMissing'] as bool,
      overlayDetected: map['overlayDetected'] as bool,
      unsecuredWifi: map['unsecuredWifi'] as bool,
      timeSpoofing: (map['timeSpoofing'] as bool?) ?? false,
      locationSpoofing: (map['locationSpoofing'] as bool?) ?? false,
      screenMirroring: (map['screenMirroring'] as bool?) ?? false,
      malwarePackages: List<String>.from(map['malwarePackages'] as List),
      smsForwarderApps: List<String>.from(map['smsForwarderApps'] as List),
      remoteAccessApps: List<String>.from(map['remoteAccessApps'] as List),
      deviceFingerprint: map['deviceFingerprint'] as String,
      appId: map['appId'] as String,
      eventId: (map['eventId'] as String?) ?? '',
      nativeThreatMask: (map['nativeThreatMask'] as int?) ?? 0,
      timestamp: (map['timestamp'] as int?) ?? 0,
      hasThreat: map['hasThreat'] as bool,
      threatCount: map['threatCount'] as int,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'isRooted': isRooted,
      'fridaDetected': fridaDetected,
      'debuggerAttached': debuggerAttached,
      'emulatorDetected': emulatorDetected,
      'hooked': hooked,
      'tampered': tampered,
      'untrustedInstaller': untrustedInstaller,
      'developerMode': developerMode,
      'adbEnabled': adbEnabled,
      'envTampering': envTampering,
      'runtimeIntegrity': runtimeIntegrity,
      'proxyDetected': proxyDetected,
      'zygiskDetected': zygiskDetected,
      'vpnDetected': vpnDetected,
      'screenRecording': screenRecording,
      'keyloggerRisk': keyloggerRisk,
      'untrustedKeyboard': untrustedKeyboard,
      'deviceLockMissing': deviceLockMissing,
      'overlayDetected': overlayDetected,
      'unsecuredWifi': unsecuredWifi,
      'timeSpoofing': timeSpoofing,
      'locationSpoofing': locationSpoofing,
      'screenMirroring': screenMirroring,
      'malwarePackages': malwarePackages,
      'smsForwarderApps': smsForwarderApps,
      'remoteAccessApps': remoteAccessApps,
      'deviceFingerprint': deviceFingerprint,
      'appId': appId,
      'eventId': eventId,
      'nativeThreatMask': nativeThreatMask,
      'timestamp': timestamp,
      'hasThreat': hasThreat,
      'threatCount': threatCount,
    };
  }
}
