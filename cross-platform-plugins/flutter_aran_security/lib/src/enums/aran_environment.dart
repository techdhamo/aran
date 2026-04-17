/// Aran Security environment modes
enum AranEnvironment {
  /// Development environment - minimal security enforcement
  dev('DEV'),

  /// UAT environment - moderate security enforcement
  uat('UAT'),

  /// Release environment - full security enforcement
  release('RELEASE');

  const AranEnvironment(this.value);
  final String value;
}
