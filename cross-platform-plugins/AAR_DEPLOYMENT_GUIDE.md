# Aran Android SDK - AAR Deployment Guide

This guide explains how to build, publish, and consume the Aran Android SDK as an AAR (Android Archive) file.

## 📦 Building the AAR

### Build Release AAR

```bash
cd aran-android-sdk
./gradlew :aran-secure:assembleRelease
```

The AAR file will be generated at:
```
aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar
```

### Build Debug AAR

```bash
./gradlew :aran-secure:assembleDebug
```

Output:
```
aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-debug.aar
```

---

## 🚀 Publishing to Maven Repository

### Option 1: Publish to Maven Central

Add to `aran-android-sdk/aran-secure/build.gradle`:

```gradle
plugins {
    id 'maven-publish'
    id 'signing'
}

publishing {
    publications {
        release(MavenPublication) {
            groupId = 'org.mazhai.aran'
            artifactId = 'aran-android-sdk'
            version = '1.0.0'
            
            artifact("$buildDir/outputs/aar/aran-secure-release.aar")
            
            pom {
                name = 'Aran Security SDK'
                description = 'Enterprise mobile security SDK with hardware attestation'
                url = 'https://aran.mazhai.org'
                
                licenses {
                    license {
                        name = 'Proprietary'
                        url = 'https://aran.mazhai.org/license'
                    }
                }
                
                developers {
                    developer {
                        id = 'aran-security'
                        name = 'Aran Security Team'
                        email = 'support@aran.mazhai.org'
                    }
                }
                
                scm {
                    connection = 'scm:git:git://github.com/aran-security/aran-android-sdk.git'
                    developerConnection = 'scm:git:ssh://github.com/aran-security/aran-android-sdk.git'
                    url = 'https://github.com/aran-security/aran-android-sdk'
                }
            }
        }
    }
    
    repositories {
        maven {
            name = "AranMaven"
            url = "https://maven.aran.mazhai.org/releases"
            credentials {
                username = project.findProperty("aranMavenUsername") ?: System.getenv("ARAN_MAVEN_USERNAME")
                password = project.findProperty("aranMavenPassword") ?: System.getenv("ARAN_MAVEN_PASSWORD")
            }
        }
    }
}

signing {
    sign publishing.publications.release
}
```

Publish:
```bash
./gradlew :aran-secure:publish
```

### Option 2: Publish to Local Maven

```bash
./gradlew :aran-secure:publishToMavenLocal
```

This installs to `~/.m2/repository/org/mazhai/aran/aran-android-sdk/1.0.0/`

---

## 📥 Consuming the AAR

### Method 1: From Maven Repository (Production)

All plugins are already configured to use this method by default.

**Cordova:**
```gradle
// cordova-plugin-aran-security/src/android/aran-security.gradle
repositories {
    maven { url "https://maven.aran.mazhai.org/releases" }
}

dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

**Capacitor:**
```gradle
// capacitor-plugin-aran-security/android/build.gradle
repositories {
    maven { url "https://maven.aran.mazhai.org/releases" }
}

dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

**React Native:**
```gradle
// react-native-aran-security/android/build.gradle
repositories {
    maven { url "https://maven.aran.mazhai.org/releases" }
}

dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

**Flutter:**
```gradle
// flutter_aran_security/android/build.gradle
repositories {
    maven { url "https://maven.aran.mazhai.org/releases" }
}

dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

### Method 2: From Local AAR File (Development)

#### Step 1: Copy AAR to Plugin

```bash
# For Cordova
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   cordova-plugin-aran-security/libs/aran-android-sdk-1.0.0.aar

# For Capacitor
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   capacitor-plugin-aran-security/android/libs/aran-android-sdk-1.0.0.aar

# For React Native
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   react-native-aran-security/android/libs/aran-android-sdk-1.0.0.aar

# For Flutter
cp aran-android-sdk/aran-secure/build/outputs/aar/aran-secure-release.aar \
   flutter_aran_security/android/libs/aran-android-sdk-1.0.0.aar
```

#### Step 2: Update Gradle Configuration

In each plugin's `build.gradle`, comment out the Maven dependency and uncomment the local AAR:

```gradle
repositories {
    flatDir {
        dirs 'libs'
    }
}

dependencies {
    // Comment this out:
    // implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
    
    // Uncomment this:
    implementation(name: 'aran-android-sdk-1.0.0', ext: 'aar')
}
```

### Method 3: From Local Maven (Development)

```bash
# Publish to local Maven
cd aran-android-sdk
./gradlew :aran-secure:publishToMavenLocal
```

All plugins are configured to use `mavenLocal()` repository, so they will automatically find the AAR.

---

## 🔧 Version Management

### Updating SDK Version

1. Update version in `aran-android-sdk/aran-secure/build.gradle`:
```gradle
android {
    defaultConfig {
        versionName "1.1.0"
    }
}
```

2. Rebuild and publish:
```bash
./gradlew :aran-secure:assembleRelease
./gradlew :aran-secure:publish
```

3. Update all plugins to use new version:
```gradle
implementation "org.mazhai.aran:aran-android-sdk:1.1.0"
```

---

## 🔐 Private Maven Repository Setup

### Using GitHub Packages

```gradle
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/aran-security/aran-android-sdk")
        credentials {
            username = project.findProperty("gpr.user") ?: System.getenv("GITHUB_USERNAME")
            password = project.findProperty("gpr.key") ?: System.getenv("GITHUB_TOKEN")
        }
    }
}
```

### Using JFrog Artifactory

```gradle
repositories {
    maven {
        url "https://aran.jfrog.io/artifactory/aran-android-sdk"
        credentials {
            username = project.findProperty("artifactoryUser") ?: System.getenv("ARTIFACTORY_USERNAME")
            password = project.findProperty("artifactoryPassword") ?: System.getenv("ARTIFACTORY_PASSWORD")
        }
    }
}
```

### Using Nexus Repository

```gradle
repositories {
    maven {
        url "https://nexus.aran.mazhai.org/repository/aran-releases/"
        credentials {
            username = project.findProperty("nexusUser") ?: System.getenv("NEXUS_USERNAME")
            password = project.findProperty("nexusPassword") ?: System.getenv("NEXUS_PASSWORD")
        }
    }
}
```

---

## 📝 Credentials Management

### Option 1: gradle.properties (Local Development)

Create `~/.gradle/gradle.properties`:
```properties
aranMavenUsername=your-username
aranMavenPassword=your-password
```

### Option 2: Environment Variables (CI/CD)

```bash
export ARAN_MAVEN_USERNAME=your-username
export ARAN_MAVEN_PASSWORD=your-password
```

### Option 3: Project-specific (Not Recommended)

Create `gradle.properties` in project root (add to `.gitignore`):
```properties
aranMavenUsername=your-username
aranMavenPassword=your-password
```

---

## 🧪 Testing AAR Integration

### Verify AAR Contents

```bash
# Extract AAR
unzip -l aran-secure-release.aar

# Should contain:
# - AndroidManifest.xml
# - classes.jar
# - R.txt
# - res/
# - jni/ (native libraries)
```

### Test in Sample App

```gradle
dependencies {
    implementation "org.mazhai.aran:aran-android-sdk:1.0.0"
}
```

```kotlin
import org.mazhai.aran.AranSecure
import org.mazhai.aran.AranEnvironment

AranSecure.start(
    context = this,
    licenseKey = "TEST_LICENSE",
    expectedSignatureSha256 = "SHA256",
    environment = AranEnvironment.DEV
)

val status = AranSecure.checkEnvironment()
println("Root detected: ${status.isRooted}")
```

---

## 🚨 Troubleshooting

### AAR Not Found

```
Could not find org.mazhai.aran:aran-android-sdk:1.0.0
```

**Solution:**
1. Verify repository URL is correct
2. Check credentials are valid
3. Ensure AAR is published: `./gradlew :aran-secure:publish`
4. Try `mavenLocal()` for local testing

### Duplicate Classes

```
Duplicate class org.mazhai.aran.AranSecure found in modules
```

**Solution:**
- Ensure only ONE dependency method is used (either Maven OR local AAR, not both)
- Clean build: `./gradlew clean`

### Missing Native Libraries

```
java.lang.UnsatisfiedLinkError: No implementation found for native method
```

**Solution:**
- Verify AAR contains `jni/` folder with `.so` files
- Check `build.gradle` includes:
```gradle
android {
    sourceSets {
        main {
            jniLibs.srcDirs = ['libs']
        }
    }
}
```

---

## 📊 Comparison: Maven vs Local AAR

| Aspect | Maven Repository | Local AAR File |
|--------|------------------|----------------|
| **Production** | ✅ Recommended | ❌ Not recommended |
| **Development** | ⚠️ Requires publish | ✅ Fast iteration |
| **Version Control** | ✅ Automatic | ❌ Manual |
| **CI/CD** | ✅ Easy | ⚠️ Requires file management |
| **Team Collaboration** | ✅ Centralized | ❌ File sharing needed |
| **Offline Support** | ❌ Requires network | ✅ Works offline |

**Recommendation:** Use Maven repository for production, local AAR for rapid development/testing.
