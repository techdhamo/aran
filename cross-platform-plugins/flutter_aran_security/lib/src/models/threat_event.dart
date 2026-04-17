import 'device_status.dart';

/// Threat detection event
class ThreatEvent {
  /// Device security status
  final DeviceStatus status;

  /// Reaction policy applied
  final String reactionPolicy;

  const ThreatEvent({
    required this.status,
    required this.reactionPolicy,
  });

  factory ThreatEvent.fromMap(Map<String, dynamic> map) {
    return ThreatEvent(
      status: DeviceStatus.fromMap(Map<String, dynamic>.from(map['status'])),
      reactionPolicy: map['reactionPolicy'] as String,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'status': status.toMap(),
      'reactionPolicy': reactionPolicy,
    };
  }
}
