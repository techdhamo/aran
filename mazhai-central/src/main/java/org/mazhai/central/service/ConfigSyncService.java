package org.mazhai.central.service;

import org.mazhai.central.api.v1.config.RaspConfigResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Multi-Tenant Configuration Merge Engine
 * Implements: Global + Tenant Blacklist - Tenant Whitelist
 */
@Service
public class ConfigSyncService {

    private static final Logger log = LoggerFactory.getLogger(ConfigSyncService.class);

    /**
     * Merge Strategy: Global + Client Blacklist - Client Whitelist
     * 
     * @param os Operating system (android/ios)
     * @param licenseKey Client license key
     * @return Personalized RASP configuration
     */
    public RaspConfigResponse buildPersonalizedConfig(String os, String licenseKey) {
        log.info("Building personalized config for os={}, license={}", os, licenseKey);

        // Step A: Fetch Global Threat Intel for the OS
        Set<String> globalMalware = getGlobalMalwarePackages(os);
        Set<String> globalSms = getGlobalSmsForwarders(os);
        Set<String> globalRemoteAccess = getGlobalRemoteAccessApps(os);
        Set<String> globalSslPins = getGlobalSslPins();

        // Step B: Fetch Tenant Blacklist (client-specific additions)
        Set<String> tenantMalwareAdditions = getTenantBlacklistMalware(licenseKey);
        Set<String> tenantSmsAdditions = getTenantBlacklistSms(licenseKey);
        Set<String> tenantRemoteAccessAdditions = getTenantBlacklistRemoteAccess(licenseKey);

        // Step C: Fetch Tenant Whitelist (client-specific exceptions)
        Set<String> tenantMalwareExceptions = getTenantWhitelistMalware(licenseKey);
        Set<String> tenantSmsExceptions = getTenantWhitelistSms(licenseKey);
        Set<String> tenantRemoteAccessExceptions = getTenantWhitelistRemoteAccess(licenseKey);

        // Merge: (Global + Blacklist) - Whitelist
        List<String> finalMalware = mergeAndFilter(globalMalware, tenantMalwareAdditions, tenantMalwareExceptions);
        List<String> finalSms = mergeAndFilter(globalSms, tenantSmsAdditions, tenantSmsExceptions);
        List<String> finalRemoteAccess = mergeAndFilter(globalRemoteAccess, tenantRemoteAccessAdditions, tenantRemoteAccessExceptions);

        // SSL pins (no whitelist for pins - either pinned or not)
        List<String> finalSslPins = new ArrayList<>(globalSslPins);

        // Build active policy (tenant overrides or global defaults)
        RaspConfigResponse.ActivePolicy policy = buildActivePolicy(licenseKey);

        log.info("Personalized config built: malware={}, sms={}, remote={}", 
            finalMalware.size(), finalSms.size(), finalRemoteAccess.size());

        // Blinded TLS pins for Phantom Channel zero-knowledge verification
        List<RaspConfigResponse.TlsPinBlinded> blindedPins = List.of(
            new RaspConfigResponse.TlsPinBlinded(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // PRODUCTION: pre-blinded SHA256(salt || pin_hash)
                "api.aran.mazhai.org"
            ),
            new RaspConfigResponse.TlsPinBlinded(
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "api.aran.mazhai.org"
            )
        );

        return new RaspConfigResponse(
            "v1.1.0",
            os,
            finalMalware,
            finalSms,
            finalRemoteAccess,
            finalSslPins,
            policy,
            60,
            blindedPins,
            3  // default_reaction_policy: KILL_APP
        );
    }

    /**
     * Core Merge Logic: (Global + Additions) - Exceptions
     */
    private List<String> mergeAndFilter(Set<String> global, Set<String> additions, Set<String> exceptions) {
        Set<String> merged = new HashSet<>(global);
        merged.addAll(additions);  // Add tenant-specific blacklist
        merged.removeAll(exceptions);  // Remove tenant-specific whitelist
        return new ArrayList<>(merged);
    }

    /**
     * Build active policy with tenant overrides
     */
    private RaspConfigResponse.ActivePolicy buildActivePolicy(String licenseKey) {
        // TODO: Fetch from TenantConfig table
        // For now, return production defaults
        return new RaspConfigResponse.ActivePolicy(
            true,  // killOnRoot
            true,  // killOnFrida
            true,  // killOnDebugger
            true,  // killOnEmulator
            true,  // killOnHook
            true,  // killOnTamper
            true,  // killOnUntrustedInstaller
            true,  // killOnDeveloperMode
            true,  // killOnAdbEnabled
            false, // killOnProxy
            false, // killOnVpn
            false  // killOnMalware
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Global Threat Intel (Aran's Baseline)
    // TODO: Replace with JPA repository queries
    // ══════════════════════════════════════════════════════════════════

    private Set<String> getGlobalMalwarePackages(String os) {
        if ("android".equalsIgnoreCase(os)) {
            return Set.of(
                "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
                "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
                "me.phh.superuser", "com.kingouser.com", "de.robv.android.xposed.installer",
                "org.lsposed.manager", "io.github.lsposed.manager", "com.saurik.substrate",
                "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
                "com.ramdroid.appquarantine", "com.formyhm.hideroot",
                "com.metasploit.stage", "com.tencent.ig.joker",
                "com.android.provision.confirm", "com.android.power.supervisor",
                "com.android.vendinc", "com.android.vendinh",
                "com.psiphon3", "com.psiphon3.subscription"
            );
        } else {
            // iOS jailbreak paths
            return Set.of(
                "/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
                "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/"
            );
        }
    }

    private Set<String> getGlobalSmsForwarders(String os) {
        if ("android".equalsIgnoreCase(os)) {
            return Set.of(
                "com.smsfwd", "com.jbak2.smsforwarder", "com.sms.forwarder",
                "com.frfrfr.smsforward", "com.smsforward.autoforward",
                "com.mazenrashed.smsforward", "ru.ivslab.smsforwarder",
                "com.elado.smsforwarder", "com.sms.auto.forwarder",
                "com.sms.gateway", "com.macrodroid.makro", "com.llamalab.automate"
            );
        } else {
            // iOS malicious URL schemes
            return Set.of("cydia://", "sileo://", "zbra://", "filza://", "activator://");
        }
    }

    private Set<String> getGlobalRemoteAccessApps(String os) {
        if ("android".equalsIgnoreCase(os)) {
            return Set.of(
                "com.teamviewer.quicksupport.market", "com.teamviewer.host.market",
                "com.teamviewer.teamviewer.market", "com.anydesk.anydeskandroid",
                "com.realvnc.viewer.android", "com.bomgar.thinclient.android",
                "com.logmein.rescuemobile", "com.splashtop.remote.pad.v2",
                "com.rsupport.mvagent", "com.supremocontrol.supremo",
                "org.ArcticFoxTech.DroidCam", "com.screenmirroring.casttv",
                "com.mobizen.mirroring", "com.deskdock.desk",
                "com.koushikdutta.vysor", "com.apowersoft.mirror"
            );
        } else {
            return Set.of();
        }
    }

    private Set<String> getGlobalSslPins() {
        return Set.of(
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Tenant-Specific Blacklist (Client Additions)
    // TODO: Replace with JPA repository queries
    // ══════════════════════════════════════════════════════════════════

    private Set<String> getTenantBlacklistMalware(String licenseKey) {
        // Example: Bank A wants to block their competitor's app
        if ("BANK_A_LICENSE".equals(licenseKey)) {
            return Set.of("com.competitor.bankapp");
        }
        return Set.of();
    }

    private Set<String> getTenantBlacklistSms(String licenseKey) {
        return Set.of();
    }

    private Set<String> getTenantBlacklistRemoteAccess(String licenseKey) {
        return Set.of();
    }

    // ══════════════════════════════════════════════════════════════════
    // Tenant-Specific Whitelist (Client Exceptions)
    // TODO: Replace with JPA repository queries
    // ══════════════════════════════════════════════════════════════════

    private Set<String> getTenantWhitelistMalware(String licenseKey) {
        return Set.of();
    }

    private Set<String> getTenantWhitelistSms(String licenseKey) {
        return Set.of();
    }

    private Set<String> getTenantWhitelistRemoteAccess(String licenseKey) {
        // Example: Bank B uses TeamViewer for customer support
        if ("BANK_B_LICENSE".equals(licenseKey)) {
            return Set.of("com.teamviewer.quicksupport.market");
        }
        return Set.of();
    }
}
