/**
 * ARAN RASP ENGINE - Android AAR Package
 * 
 * This NPM package provides the Android AAR for ARAN RASP Engine.
 * The AAR is fetched from the remote Maven repository at build time.
 * 
 * Usage:
 * - This package is primarily for NPM-based distribution
 * - The actual AAR is hosted on Maven repository
 * - Use the Gradle dependency in your Android project:
 *   implementation 'com.aran.security:rasp-core:1.0.0@aar'
 */

module.exports = {
  name: '@aran-security/rasp-core-android',
  version: '1.0.0',
  description: 'ARAN RASP Engine Android Native Library (AAR)',
  mavenArtifact: {
    groupId: 'com.aran.security',
    artifactId: 'rasp-core',
    version: '1.0.0',
    packaging: 'aar',
    repository: 'https://maven.aran-security.com/releases'
  },
  getGradleDependency() {
    return `implementation '${this.mavenArtifact.groupId}:${this.mavenArtifact.artifactId}:${this.mavenArtifact.version}@aar'`;
  }
};
