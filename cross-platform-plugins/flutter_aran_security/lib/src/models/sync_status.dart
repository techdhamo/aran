/// Cloud sync status
class SyncStatus {
  /// Last sync timestamp (milliseconds since epoch)
  final int lastSyncTimestamp;

  /// Current request ID for fraud tracking
  final String currentRequestId;

  const SyncStatus({
    required this.lastSyncTimestamp,
    required this.currentRequestId,
  });

  factory SyncStatus.fromMap(Map<String, dynamic> map) {
    return SyncStatus(
      lastSyncTimestamp: map['lastSyncTimestamp'] as int,
      currentRequestId: map['currentRequestId'] as String,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'lastSyncTimestamp': lastSyncTimestamp,
      'currentRequestId': currentRequestId,
    };
  }
}
