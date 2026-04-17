package org.mazhai.aran

import android.app.Application
import org.mazhai.aran.core.AranNative

/**
 * ARAN Application Class
 * 
 * This class extends Application to provide early initialization of the RASP engine.
 * It should be referenced in the AndroidManifest.xml as the application class.
 * 
 * Security Requirements:
 * - Initialize RASP engine as early as possible in the application lifecycle
 * - Perform integrity checks before app components are created
 * - Protect against tampering and reverse engineering
 */
class Aran : Application() {

    companion object {
        private var isInitialized = false
    }

    override fun onCreate() {
        super.onCreate()
        
        // Initialize ARAN RASP engine
        if (!isInitialized) {
            try {
                AranNative.initialize()
                isInitialized = true
                android.util.Log.d("ARAN", "RASP engine initialized successfully")
            } catch (e: Exception) {
                android.util.Log.e("ARAN", "Failed to initialize RASP engine", e)
            }
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        
        // Shutdown ARAN RASP engine
        try {
            AranNative.shutdown()
            isInitialized = false
            android.util.Log.d("ARAN", "RASP engine shutdown successfully")
        } catch (e: Exception) {
            android.util.Log.e("ARAN", "Failed to shutdown RASP engine", e)
        }
    }

    /**
     * Check if RASP engine is initialized
     */
    fun isRaspInitialized(): Boolean {
        return isInitialized
    }
}
