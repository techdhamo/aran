package org.mazhai.central.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mazhai.central.api.v1.config.RaspConfigResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for Multi-Tenant Config Merge Engine
 */
class ConfigSyncServiceTest {

    private ConfigSyncService configSyncService;

    @BeforeEach
    void setUp() {
        configSyncService = new ConfigSyncService();
    }

    @Test
    void testBuildPersonalizedConfig_Android_DefaultTenant() {
        // Given: Default tenant with no custom whitelist/blacklist
        String os = "android";
        String licenseKey = "DEFAULT_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: Should return global threat intel
        assertNotNull(response);
        assertEquals("android", response.osType());
        assertEquals("v1.1.0", response.configVersion());
        assertTrue(response.malwarePackages().contains("com.topjohnwu.magisk"));
        assertTrue(response.malwarePackages().contains("eu.chainfire.supersu"));
        assertTrue(response.smsForwarders().contains("com.smsfwd"));
        assertTrue(response.remoteAccessApps().contains("com.teamviewer.quicksupport.market"));
        assertEquals(60, response.syncIntervalSeconds());
    }

    @Test
    void testBuildPersonalizedConfig_iOS_DefaultTenant() {
        // Given: iOS tenant
        String os = "ios";
        String licenseKey = "DEFAULT_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: Should return iOS-specific threat intel (jailbreak paths)
        assertNotNull(response);
        assertEquals("ios", response.osType());
        assertTrue(response.malwarePackages().contains("/Applications/Cydia.app"));
        assertTrue(response.malwarePackages().contains("/bin/bash"));
        assertTrue(response.smsForwarders().contains("cydia://"));
        assertTrue(response.smsForwarders().contains("sileo://"));
    }

    @Test
    void testMergeStrategy_TenantBlacklist_BankA() {
        // Given: Bank A wants to block competitor app
        String os = "android";
        String licenseKey = "BANK_A_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: Should include global + tenant blacklist
        assertNotNull(response);
        assertTrue(response.malwarePackages().contains("com.topjohnwu.magisk")); // Global
        assertTrue(response.malwarePackages().contains("com.competitor.bankapp")); // Tenant addition
    }

    @Test
    void testMergeStrategy_TenantWhitelist_BankB() {
        // Given: Bank B whitelists TeamViewer for customer support
        String os = "android";
        String licenseKey = "BANK_B_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: TeamViewer should be REMOVED from remote access list
        assertNotNull(response);
        assertFalse(response.remoteAccessApps().contains("com.teamviewer.quicksupport.market")); // Whitelisted!
        assertTrue(response.malwarePackages().contains("com.topjohnwu.magisk")); // Global still present
    }

    @Test
    void testActivePolicy_DefaultValues() {
        // Given: Default tenant
        String os = "android";
        String licenseKey = "DEFAULT_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: Should have production-grade policy
        RaspConfigResponse.ActivePolicy policy = response.activePolicy();
        assertNotNull(policy);
        assertTrue(policy.killOnRoot());
        assertTrue(policy.killOnFrida());
        assertTrue(policy.killOnDebugger());
        assertTrue(policy.killOnEmulator());
        assertTrue(policy.killOnHook());
        assertTrue(policy.killOnTamper());
        assertFalse(policy.killOnProxy()); // Telemetry only
        assertFalse(policy.killOnVpn()); // Telemetry only
        assertFalse(policy.killOnMalware()); // Alert only
    }

    @Test
    void testSslPins_IncludedInResponse() {
        // Given: Any tenant
        String os = "android";
        String licenseKey = "DEFAULT_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: SSL pins should be present
        assertNotNull(response.sslPins());
        assertFalse(response.sslPins().isEmpty());
        assertTrue(response.sslPins().get(0).startsWith("sha256/"));
    }

    @Test
    void testMalwarePackages_NoEmptyLists() {
        // Given: Any tenant
        String os = "android";
        String licenseKey = "DEFAULT_LICENSE";

        // When: Building personalized config
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig(os, licenseKey);

        // Then: Lists should never be null or empty
        assertNotNull(response.malwarePackages());
        assertNotNull(response.smsForwarders());
        assertNotNull(response.remoteAccessApps());
        assertNotNull(response.sslPins());
        assertFalse(response.malwarePackages().isEmpty());
        assertFalse(response.smsForwarders().isEmpty());
    }

    @Test
    void testConfigVersion_Consistency() {
        // Given: Multiple tenants
        RaspConfigResponse response1 = configSyncService.buildPersonalizedConfig("android", "TENANT_1");
        RaspConfigResponse response2 = configSyncService.buildPersonalizedConfig("android", "TENANT_2");

        // Then: Config version should be consistent
        assertEquals(response1.configVersion(), response2.configVersion());
    }

    @Test
    void testSyncInterval_DefaultValue() {
        // Given: Any tenant
        RaspConfigResponse response = configSyncService.buildPersonalizedConfig("android", "DEFAULT");

        // Then: Sync interval should be 60 seconds
        assertEquals(60, response.syncIntervalSeconds());
    }
}
