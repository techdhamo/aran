/// Threat reaction policies
enum ReactionPolicy {
  /// Log only - no user interaction
  logOnly('LOG_ONLY'),

  /// Warn user with dialog
  warnUser('WARN_USER'),

  /// Block API calls
  blockApi('BLOCK_API'),

  /// Terminate application
  killApp('KILL_APP'),

  /// Block and report to backend
  blockAndReport('BLOCK_AND_REPORT'),

  /// Custom handling - delegate to app
  custom('CUSTOM');

  const ReactionPolicy(this.value);
  final String value;
}
