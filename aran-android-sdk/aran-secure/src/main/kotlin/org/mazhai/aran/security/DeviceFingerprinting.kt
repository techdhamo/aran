package org.mazhai.aran.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Log
import android.view.WindowManager
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class DeviceFingerprinting private constructor(private val context: Context) {
    
    companion object {
        @Volatile
        private var INSTANCE: DeviceFingerprinting? = null
        
        fun getInstance(context: Context): DeviceFingerprinting {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: DeviceFingerprinting(context.applicationContext).also { INSTANCE = it }
            }
        }
        
        @Volatile
        private var fingerprintGenerated = AtomicBoolean(false)
        @Volatile
        private var cachedFingerprint: String? = null
    }
    
    private val antiFridaHelper = AntiFridaHelper.getInstance(context)
    
    /**
     * Generate comprehensive device fingerprint
     */
    fun generateDeviceFingerprint(): String {
        if (fingerprintGenerated.get() && cachedFingerprint != null) {
            Log.d("AranFingerprint", "Returning cached device fingerprint")
            return cachedFingerprint!!
        }
        
        try {
            Log.i("AranFingerprint", "Generating comprehensive device fingerprint...")
            
            val fingerprintData = StringBuilder()
            
            // 1. Hardware identifiers
            fingerprintData.append(collectHardwareIdentifiers())
            fingerprintData.append("|")
            
            // 2. System configuration
            fingerprintData.append(collectSystemConfiguration())
            fingerprintData.append("|")
            
            // 3. Security indicators
            fingerprintData.append(collectSecurityIndicators())
            fingerprintData.append("|")
            
            // 4. Application environment
            fingerprintData.append(collectApplicationEnvironment())
            fingerprintData.append("|")
            
            // 5. Network configuration
            fingerprintData.append(collectNetworkConfiguration())
            fingerprintData.append("|")
            
            // 6. Sensor data
            fingerprintData.append(collectSensorData())
            fingerprintData.append("|")
            
            // 7. File system indicators
            fingerprintData.append(collectFileSystemIndicators())
            fingerprintData.append("|")

            // 8. Native fingerprint
            fingerprintData.append(antiFridaHelper.getDeviceFingerprint())
            
            // Generate hash of all collected data
            val fingerprint = generateHash(fingerprintData.toString())
            
            // Add salt and timestamp
            val salt = generateSalt()
            val timestamp = System.currentTimeMillis().toString()
            val finalFingerprint = generateHash("$fingerprint$salt$timestamp")
            
            cachedFingerprint = finalFingerprint
            fingerprintGenerated.set(true)
            
            Log.i("AranFingerprint", "Device fingerprint generated successfully")
            Log.d("AranFingerprint", "Fingerprint preview: ${finalFingerprint.take(16)}...")
            
            return finalFingerprint
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error generating device fingerprint", e)
            return generateFallbackFingerprint()
        }
    }
    
    /**
     * Collect hardware identifiers
     */
    private fun collectHardwareIdentifiers(): String {
        val hardware = StringBuilder()
        
        try {
            // Build information
            hardware.append("BRAND:${Build.BRAND};")
            hardware.append("MANUFACTURER:${Build.MANUFACTURER};")
            hardware.append("MODEL:${Build.MODEL};")
            hardware.append("PRODUCT:${Build.PRODUCT};")
            hardware.append("DEVICE:${Build.DEVICE};")
            hardware.append("BOARD:${Build.BOARD};")
            hardware.append("HARDWARE:${Build.HARDWARE};")
            
            // Serial number (with permission check)
            try {
                val serial = Build.getSerial()
                if (serial != null && serial != "unknown") {
                    hardware.append("SERIAL:$serial;")
                }
            } catch (e: Exception) {
                Log.w("AranFingerprint", "Could not access serial number", e)
            }
            
            // CPU info
            hardware.append("CPU_ABI:${Build.SUPPORTED_ABIS[0]};")
            if (Build.SUPPORTED_ABIS.size > 1) {
                hardware.append("CPU_ABI2:${Build.SUPPORTED_ABIS[1]};")
            }
            
            // Display information
            val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val metrics = android.util.DisplayMetrics()
            wm.defaultDisplay.getMetrics(metrics)
            hardware.append("DENSITY:${metrics.densityDpi};")
            hardware.append("RESOLUTION:${metrics.widthPixels}x${metrics.heightPixels};")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting hardware identifiers", e)
        }
        
        return hardware.toString()
    }
    
    /**
     * Collect system configuration
     */
    private fun collectSystemConfiguration(): String {
        val system = StringBuilder()
        
        try {
            // Android version information
            system.append("SDK_INT:${Build.VERSION.SDK_INT};")
            system.append("RELEASE:${Build.VERSION.RELEASE};")
            system.append("INCREMENTAL:${Build.VERSION.INCREMENTAL};")
            system.append("CODENAME:${Build.VERSION.CODENAME};")
            
            // Build tags and type
            system.append("TAGS:${Build.TAGS};")
            system.append("TYPE:${Build.TYPE};")
            system.append("USER:${Build.USER};")
            
            // System properties
            system.append("FINGERPRINT:${Build.FINGERPRINT};")
            system.append("HOST:${Build.HOST};")
            system.append("TIME:${Build.TIME};")
            
            // Locale
            val locale = Locale.getDefault()
            system.append("LOCALE:$locale;")
            
            // Timezone
            system.append("TIMEZONE:${TimeZone.getDefault().id};")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting system configuration", e)
        }
        
        return system.toString()
    }
    
    /**
     * Collect security indicators
     */
    private fun collectSecurityIndicators(): String {
        val security = StringBuilder()
        
        try {
            // Development settings
            val isDevelopmentMode = Settings.Secure.getInt(
                context.contentResolver, 
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
            security.append("DEV_MODE:$isDevelopmentMode;")
            
            // ADB debugging
            val adbEnabled = Settings.Secure.getInt(
                context.contentResolver, 
                Settings.Global.ADB_ENABLED, 0) == 1
            security.append("ADB_ENABLED:$adbEnabled;")
            
            // Unknown sources
            val unknownSources = Settings.Secure.getInt(
                context.contentResolver, 
                Settings.Global.INSTALL_NON_MARKET_APPS, 0) == 1
            security.append("UNKNOWN_SOURCES:$unknownSources;")

            // Debugging properties using reflection
            try {
                val systemPropertiesClass = Class.forName("android.os.SystemProperties")
                val getIntMethod = systemPropertiesClass.getMethod("getInt", String::class.java, Int::class.javaPrimitiveType)
                val getMethod = systemPropertiesClass.getMethod("get", String::class.java, String::class.java)

                val isDebuggable = getIntMethod.invoke(null, "ro.debuggable", 0) as Int
                val isSecure = getIntMethod.invoke(null, "ro.secure", 1) as Int
                val selinuxStatus = getMethod.invoke(null, "ro.build.selinux", "unknown") as String

                security.append("DEBUGGABLE:$isDebuggable;")
                security.append("SECURE:$isSecure;")
                security.append("SELINUX:$selinuxStatus;")
            } catch (e: Exception) {
                Log.w("AranFingerprint", "Could not access system properties", e)
                security.append("DEBUGGABLE:unknown;")
                security.append("SECURE:unknown;")
                security.append("SELINUX:unknown;")
            }
            
            // Check for root indicators
            // This would require RootBeer library integration
            security.append("ROOT_DETECTED:false;")
            
            // Check for Frida
            val fridaDetected = AntiFridaHelper.isFridaDetected()
            security.append("FRIDA_DETECTED:$fridaDetected;")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting security indicators", e)
        }
        
        return security.toString()
    }
    
    /**
     * Collect application environment
     */
    private fun collectApplicationEnvironment(): String {
        val appEnv = StringBuilder()
        
        try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(context.packageName, 0)
            
            // App information
            appEnv.append("PACKAGE_NAME:${context.packageName};")
            appEnv.append("VERSION_CODE:${getVersionCode()};")
            appEnv.append("VERSION_NAME:${getVersionName()};")
            appEnv.append("TARGET_SDK:${appInfo.targetSdkVersion};")
            
            // Installation source
            val installer = pm.getInstallerPackageName(context.packageName)
            appEnv.append("INSTALLER:${installer ?: "unknown"};")
            
            // App flags
            appEnv.append("FLAGS:${appInfo.flags};")
            
            // First install time
            val packageInfo = pm.getPackageInfo(context.packageName, 0)
            appEnv.append("FIRST_INSTALL:${packageInfo.firstInstallTime};")
            
            // Last update time
            appEnv.append("LAST_UPDATE:${packageInfo.lastUpdateTime};")
            
            // Check for suspicious apps
            appEnv.append("SUSPICIOUS_APPS:${countSuspiciousApps()};")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting application environment", e)
        }
        
        return appEnv.toString()
    }
    
    /**
     * Collect network configuration
     */
    private fun collectNetworkConfiguration(): String {
        val network = StringBuilder()
        
        try {
            // Telephony information
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            network.append("NETWORK_COUNTRY:${tm.networkCountryIso};")
            network.append("NETWORK_OPERATOR:${tm.networkOperatorName};")
            network.append("SIM_COUNTRY:${tm.simCountryIso};")
            network.append("SIM_OPERATOR:${tm.simOperatorName};")
            network.append("PHONE_TYPE:${tm.phoneType};")
            
            // Network interfaces
            val interfaces = Collections.list<java.net.NetworkInterface>(java.net.NetworkInterface.getNetworkInterfaces())
            val interfaceNames = interfaces.map { it.name }.sorted()
            network.append("NET_INTERFACES:${interfaceNames.joinToString(",")};")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting network configuration", e)
        }
        
        return network.toString()
    }
    
    /**
     * Collect sensor data
     */
    private fun collectSensorData(): String {
        val sensors = StringBuilder()
        
        try {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val sensorList = sensorManager.getSensorList(Sensor.TYPE_ALL)
            val sensorTypes = sensorList.map { it.stringType }.sorted()
            
            sensors.append("SENSORS:${sensorTypes.joinToString(",")};")
            sensors.append("SENSOR_COUNT:${sensorList.size};")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting sensor data", e)
        }
        
        return sensors.toString()
    }
    
    /**
     * Collect file system indicators
     */
    private fun collectFileSystemIndicators(): String {
        val fileSystem = StringBuilder()
        
        try {
            // Check for suspicious files
            val suspiciousPaths = arrayOf(
                "/system/app/Superuser.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/data/data/com.noshufou.android.su",
                "/data/data/eu.chainfire.supersu"
            )
            
            var suspiciousFileCount = 0
            for (path in suspiciousPaths) {
                if (File(path).exists()) {
                    suspiciousFileCount++
                }
            }
            fileSystem.append("SUSPICIOUS_FILES:$suspiciousFileCount;")
            
            // Check system partition properties
            try {
                val process = Runtime.getRuntime().exec("mount")
                val reader = BufferedReader(java.io.InputStreamReader(process.inputStream))
                var writableSystemPartitions = 0

                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.contains("/system") && line.contains("rw,")) {
                        writableSystemPartitions++
                    }
                }
                reader.close()
                process.destroy()

                fileSystem.append("WRITABLE_SYSTEM:$writableSystemPartitions;")

            } catch (e: Exception) {
                fileSystem.append("WRITABLE_SYSTEM:unknown;")
            }
            
            // Check available storage
            val dataDir = context.filesDir
            val totalSpace = dataDir.totalSpace
            val freeSpace = dataDir.freeSpace
            fileSystem.append("TOTAL_SPACE:$totalSpace;")
            fileSystem.append("FREE_SPACE:$freeSpace;")
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error collecting file system indicators", e)
        }
        
        return fileSystem.toString()
    }
    
    /**
     * Count suspicious applications
     */
    private fun countSuspiciousApps(): Int {
        var suspiciousCount = 0
        
        try {
            val pm = context.packageManager
            val suspiciousPackages = arrayOf(
                "com.koushikdutta.superuser",
                "com.noshufou.android.su",
                "eu.chainfire.supersu",
                "com.zachspong.temprootremovejb",
                "com.amphoras.shide",
                "com.devadvance.rootcloak",
                "de.robv.android.xposed.installer",
                "com.saurik.substrate"
            )
            
            for (packageName in suspiciousPackages) {
                try {
                    pm.getPackageInfo(packageName, 0)
                    suspiciousCount++
                } catch (e: PackageManager.NameNotFoundException) {
                    // Package not installed - expected
                }
            }
            
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error counting suspicious apps", e)
        }
        
        return suspiciousCount
    }
    
    /**
     * Get version code
     */
    private fun getVersionCode(): Int {
        return try {
            context.packageManager
                .getPackageInfo(context.packageName, 0).versionCode
        } catch (e: PackageManager.NameNotFoundException) {
            0
        }
    }
    
    /**
     * Get version name
     */
    private fun getVersionName(): String {
        return try {
            context.packageManager
                .getPackageInfo(context.packageName, 0).versionName ?: "unknown"
        } catch (e: PackageManager.NameNotFoundException) {
            "unknown"
        }
    }
    
    /**
     * Generate SHA-256 hash
     */
    private fun generateHash(input: String): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error generating hash", e)
            input.hashCode().toString()
        }
    }
    
    /**
     * Generate random salt
     */
    private fun generateSalt(): String {
        val random = SecureRandom()
        val salt = ByteArray(16)
        random.nextBytes(salt)
        return android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP)
    }
    
    /**
     * Generate fallback fingerprint
     */
    private fun generateFallbackFingerprint(): String {
        return try {
            val fallbackData = "${Build.FINGERPRINT}${Build.MODEL}${Build.VERSION.RELEASE}${System.currentTimeMillis()}${UUID.randomUUID()}"
            generateHash(fallbackData)
        } catch (e: Exception) {
            Log.e("AranFingerprint", "Error generating fallback fingerprint", e)
            "fallback_${System.currentTimeMillis()}"
        }
    }
    
    /**
     * Validate fingerprint consistency
     */
    fun validateFingerprintConsistency(newFingerprint: String): Boolean {
        if (cachedFingerprint == null) {
            Log.w("AranFingerprint", "No cached fingerprint available for validation")
            return false
        }
        
        val consistent = cachedFingerprint == newFingerprint
        if (!consistent) {
            Log.w("AranFingerprint", "Fingerprint inconsistency detected")
            Log.d("AranFingerprint", "Cached: ${cachedFingerprint?.take(16)}...")
            Log.d("AranFingerprint", "New: ${newFingerprint.take(16)}...")
        }
        
        return consistent
    }
    
    /**
     * Get fingerprint components for server validation
     */
    fun getFingerprintComponents(): FingerprintComponents {
        return FingerprintComponents(
            collectHardwareIdentifiers(),
            collectSystemConfiguration(),
            collectSecurityIndicators(),
            collectApplicationEnvironment(),
            collectNetworkConfiguration(),
            collectSensorData(),
            collectFileSystemIndicators(),
            antiFridaHelper.getDeviceFingerprint()
        )
    }
    
    /**
     * Fingerprint components class
     */
    data class FingerprintComponents(
        val hardware: String,
        val system: String,
        val security: String,
        val application: String,
        val network: String,
        val sensors: String,
        val fileSystem: String,
        val nativeFingerprint: String
    ) {
        fun getCombinedData(): String {
            return "$hardware|$system|$security|$application|$network|$sensors|$fileSystem|$nativeFingerprint"
        }
    }
    
    /**
     * Reset cached fingerprint
     */
    fun resetCache() {
        cachedFingerprint = null
        fingerprintGenerated.set(false)
        Log.d("AranFingerprint", "Fingerprint cache reset")
    }
}
