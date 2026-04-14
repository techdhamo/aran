plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

android {
    namespace = "org.mazhai.aran"
    compileSdk = 34
    buildToolsVersion = "34.0.0"

    defaultConfig {
        minSdk = 24
        targetSdk = 34

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }

        consumerProguardFiles("consumer-rules.pro")
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    ndkVersion = "26.1.10909125"

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // Cronet (Chromium Network Stack) for QUIC/HTTP3 Phantom Channel
    implementation("com.google.android.gms:play-services-cronet:18.1.0")
    implementation("org.chromium.net:cronet-api:119.6045.31")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "org.mazhai.aran"
                artifactId = "aran-secure"
                version = findProperty("VERSION_NAME")?.toString() ?: "1.0.0"

                pom {
                    name.set("Aran Secure")
                    description.set("Enterprise Fintech RASP SDK for Android.")
                    url.set("https://aran.mazhai.org")
                }
            }
        }
        repositories {
            maven {
                name = "AranDemobank"
                url = uri("https://maven.mazhai.org/nexus/repository/aran-demobank/")
                credentials {
                    username = "admin"
                    password = "DS@n#2k22"
                }
                isAllowInsecureProtocol = true
            }
        }
    }
}
