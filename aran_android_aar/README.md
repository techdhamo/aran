# ARAN RASP Engine - Android AAR

Cloud-native Android library for ARAN Runtime Application Self-Protection (RASP) engine.

## Overview

This package provides the Android AAR (Android Archive) for the ARAN RASP Engine. The AAR is hosted on remote repositories (Maven/NPM) and fetched at build time, enabling cloud-native library management without app redeployment.

## Repository Hosting

### Maven Repository

- **URL**: `https://maven.aran-security.com/releases`
- **Artifact**: `com.aran.security:rasp-core:1.0.0@aar`
- **Authentication**: Environment variables `ARAN_MAVEN_USERNAME` and `ARAN_MAVEN_PASSWORD`

### NPM Repository

- **URL**: `https://npm.aran-security.com`
- **Package**: `@aran-security/rasp-core-android`
- **Version**: `1.0.0`

## Usage

### Gradle Dependency

Add the Maven repository to your `build.gradle`:

```gradle
repositories {
    maven {
        url 'https://maven.aran-security.com/releases'
        credentials {
            username System.getenv('ARAN_MAVEN_USERNAME')
            password System.getenv('ARAN_MAVEN_PASSWORD')
        }
    }
}

dependencies {
    implementation 'com.aran.security:rasp-core:1.0.0@aar'
}
```

### NPM Package

Install via NPM:

```bash
npm install @aran-security/rasp-core-android
```

## Building

### Build AAR

```bash
./build_aar.sh build
```

### Publish to Maven

```bash
./build_aar.sh maven
```

### Publish to NPM

```bash
./build_aar.sh npm
```

### Build and Publish All

```bash
./build_aar.sh all
```

## Architecture

- **Native Library**: C++ core engine compiled with CMake
- **JNI Bridge**: C++ JNI bindings for native methods
- **Java Wrapper**: Java class for P/Invoke access
- **AAR Package**: Android Archive containing all components

## Security Features

- Symbol stripping and obfuscation
- Silent failure with randomized error codes
- No sensitive strings in framework code
- Obfuscated selectors for API calls

## Cloud-Native Benefits

- **Remote Updates**: Security definitions can be pushed without app redeployment
- **Version Management**: Semantic versioning for controlled rollouts
- **No UAT/Production Cycles**: Updates broadcast to all devices
- **Antivirus-like Model**: Similar to how antivirus definitions are updated

## License

Proprietary - © 2024 ARAN Security
