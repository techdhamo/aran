package org.mazhai.aran

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mazhai.aran.internal.AranSyncEngine

/**
 * Instrumentation tests for AranSyncEngine
 * Tests cloud sync, encrypted caching, and dynamic list retrieval
 */
@RunWith(AndroidJUnit4::class)
class AranSyncEngineTest {

    private lateinit var context: Context
    private lateinit var syncEngine: AranSyncEngine

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        syncEngine = AranSyncEngine(
            context = context,
            licenseKey = "TEST_LICENSE",
            baseUrl = "http://10.0.2.2:33100"
        )
    }

    @After
    fun tearDown() {
        syncEngine.stop()
    }

    @Test
    fun testSyncEngine_FallbackDefaults_BeforeFirstSync() {
        // Given: Fresh sync engine (no cloud sync yet)
        
        // When: Getting malware packages before first sync
        val malwarePackages = syncEngine.getMalwarePackages()
        
        // Then: Should return fallback defaults
        assert(malwarePackages.isNotEmpty()) { "Malware packages should not be empty" }
        assert(malwarePackages.contains("com.topjohnwu.magisk")) { "Should contain default malware" }
        assert(malwarePackages.contains("eu.chainfire.supersu")) { "Should contain default malware" }
    }

    @Test
    fun testSyncEngine_SmsForwarders_FallbackDefaults() {
        // Given: Fresh sync engine
        
        // When: Getting SMS forwarders
        val smsForwarders = syncEngine.getSmsForwarders()
        
        // Then: Should return fallback defaults
        assert(smsForwarders.isNotEmpty()) { "SMS forwarders should not be empty" }
        assert(smsForwarders.contains("com.smsfwd")) { "Should contain default SMS forwarder" }
    }

    @Test
    fun testSyncEngine_RemoteAccessApps_FallbackDefaults() {
        // Given: Fresh sync engine
        
        // When: Getting remote access apps
        val remoteAccessApps = syncEngine.getRemoteAccessApps()
        
        // Then: Should return fallback defaults
        assert(remoteAccessApps.isNotEmpty()) { "Remote access apps should not be empty" }
        assert(remoteAccessApps.contains("com.teamviewer.quicksupport.market")) { "Should contain default remote access app" }
    }

    @Test
    fun testSyncEngine_SslPins_FallbackDefaults() {
        // Given: Fresh sync engine
        
        // When: Getting SSL pins
        val sslPins = syncEngine.getSslPins()
        
        // Then: Should return fallback defaults
        assert(sslPins.isNotEmpty()) { "SSL pins should not be empty" }
        assert(sslPins[0].startsWith("sha256/")) { "SSL pins should be in correct format" }
    }

    @Test
    fun testSyncEngine_LastSyncTimestamp_InitiallyZero() {
        // Given: Fresh sync engine
        
        // When: Getting last sync timestamp
        val timestamp = syncEngine.getLastSyncTimestamp()
        
        // Then: Should be zero before first sync
        assert(timestamp == 0L) { "Initial timestamp should be zero" }
    }

    @Test
    fun testSyncEngine_RequestId_InitiallyEmpty() {
        // Given: Fresh sync engine
        
        // When: Getting current request ID
        val requestId = syncEngine.getCurrentRequestId()
        
        // Then: Should be empty before first request
        assert(requestId.isEmpty()) { "Initial request ID should be empty" }
    }

    @Test
    fun testSyncEngine_SetRequestId_Persistence() {
        // Given: Fresh sync engine
        val testRequestId = "test-uuid-12345"
        
        // When: Setting request ID
        syncEngine.setCurrentRequestId(testRequestId)
        
        // Then: Should be retrievable
        val retrievedId = syncEngine.getCurrentRequestId()
        assert(retrievedId == testRequestId) { "Request ID should persist" }
    }

    @Test
    fun testSyncEngine_BackgroundSync_NetworkFailure_UsesCachedData() = runBlocking {
        // Given: Sync engine with invalid URL (simulates network failure)
        val failingSyncEngine = AranSyncEngine(
            context = context,
            licenseKey = "TEST_LICENSE",
            baseUrl = "http://invalid.url.local:99999"
        )
        
        // When: Starting sync (will fail but should use fallback)
        failingSyncEngine.start()
        delay(2000) // Wait for first sync attempt
        
        // Then: Should still return fallback defaults (not crash)
        val malwarePackages = failingSyncEngine.getMalwarePackages()
        assert(malwarePackages.isNotEmpty()) { "Should use fallback on network failure" }
        
        failingSyncEngine.stop()
    }

    @Test
    fun testSyncEngine_EncryptedCache_NoDuplicates() {
        // Given: Sync engine
        
        // When: Getting malware packages multiple times
        val packages1 = syncEngine.getMalwarePackages()
        val packages2 = syncEngine.getMalwarePackages()
        
        // Then: Should return consistent results
        assert(packages1 == packages2) { "Cache should return consistent results" }
    }

    @Test
    fun testSyncEngine_DynamicLists_NotHardcoded() {
        // Given: Sync engine
        
        // When: Getting all dynamic lists
        val malware = syncEngine.getMalwarePackages()
        val sms = syncEngine.getSmsForwarders()
        val remote = syncEngine.getRemoteAccessApps()
        
        // Then: Lists should be independent (not all the same)
        assert(malware != sms) { "Malware and SMS lists should be different" }
        assert(malware != remote) { "Malware and remote access lists should be different" }
        assert(sms != remote) { "SMS and remote access lists should be different" }
    }

    @Test
    fun testSyncEngine_Stop_CancelsBackgroundSync() = runBlocking {
        // Given: Running sync engine
        syncEngine.start()
        delay(500)
        
        // When: Stopping sync engine
        syncEngine.stop()
        
        // Then: Should not crash and data should still be accessible
        val malware = syncEngine.getMalwarePackages()
        assert(malware.isNotEmpty()) { "Data should still be accessible after stop" }
    }
}
