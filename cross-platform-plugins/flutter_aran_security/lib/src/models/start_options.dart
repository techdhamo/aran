import '../enums/aran_environment.dart';

/// Configuration options for initializing Aran Security SDK
class StartOptions {
  /// Your Aran license key
  final String licenseKey;

  /// Expected APK/IPA signature SHA-256
  final String expectedSignature;

  /// Environment mode
  final AranEnvironment environment;

  /// Aran Cloud backend URL (optional)
  final String? backendUrl;

  const StartOptions({
    required this.licenseKey,
    required this.expectedSignature,
    required this.environment,
    this.backendUrl,
  });

  Map<String, dynamic> toMap() {
    return {
      'licenseKey': licenseKey,
      'expectedSignature': expectedSignature,
      'environment': environment.value,
      if (backendUrl != null) 'backendUrl': backendUrl,
    };
  }
}
