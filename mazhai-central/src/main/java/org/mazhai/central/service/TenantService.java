package org.mazhai.central.service;

import org.mazhai.central.domain.Tenant;
import org.mazhai.central.domain.TenantBlacklist;
import org.mazhai.central.domain.TenantWhitelist;
import org.mazhai.central.repository.TenantBlacklistRepository;
import org.mazhai.central.repository.TenantRepository;
import org.mazhai.central.repository.TenantWhitelistRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Tenant Service - Business Logic Layer
 * 
 * Handles tenant CRUD operations, configuration management,
 * whitelist/blacklist operations, and SSL certificate pinning.
 */
@Service
@Transactional
public class TenantService {

    private static final Logger log = LoggerFactory.getLogger(TenantService.class);

    private final TenantRepository tenantRepository;
    private final TenantWhitelistRepository whitelistRepository;
    private final TenantBlacklistRepository blacklistRepository;

    public TenantService(
        TenantRepository tenantRepository,
        TenantWhitelistRepository whitelistRepository,
        TenantBlacklistRepository blacklistRepository
    ) {
        this.tenantRepository = tenantRepository;
        this.whitelistRepository = whitelistRepository;
        this.blacklistRepository = blacklistRepository;
    }

    // ══════════════════════════════════════════════════════════════════
    // Tenant CRUD Operations
    // ══════════════════════════════════════════════════════════════════

    public Tenant createTenant(Tenant tenant) {
        if (tenantRepository.existsByLicenseKey(tenant.getLicenseKey())) {
            throw new IllegalArgumentException("License key already exists: " + tenant.getLicenseKey());
        }
        
        if (tenantRepository.existsByOrganizationName(tenant.getOrganizationName())) {
            throw new IllegalArgumentException("Organization name already exists: " + tenant.getOrganizationName());
        }

        log.info("Creating new tenant: {} ({})", tenant.getOrganizationName(), tenant.getLicenseKey());
        return tenantRepository.save(tenant);
    }

    public Optional<Tenant> getTenantByLicenseKey(String licenseKey) {
        return tenantRepository.findByLicenseKey(licenseKey);
    }

    public Optional<Tenant> getTenantById(Long id) {
        return tenantRepository.findById(id);
    }

    public List<Tenant> getAllTenants() {
        return tenantRepository.findAll();
    }

    public Tenant updateTenant(Long id, Tenant updatedTenant) {
        Tenant existing = tenantRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + id));

        existing.setOrganizationName(updatedTenant.getOrganizationName());
        existing.setContactEmail(updatedTenant.getContactEmail());
        existing.setContactPhone(updatedTenant.getContactPhone());
        existing.setStatus(updatedTenant.getStatus());
        existing.setTier(updatedTenant.getTier());
        existing.setMaxDevices(updatedTenant.getMaxDevices());

        log.info("Updated tenant: {}", existing.getLicenseKey());
        return tenantRepository.save(existing);
    }

    public void deleteTenant(Long id) {
        Tenant tenant = tenantRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + id));

        log.warn("Deleting tenant: {} ({})", tenant.getOrganizationName(), tenant.getLicenseKey());
        tenantRepository.delete(tenant);
    }

    // ══════════════════════════════════════════════════════════════════
    // RASP Behavior Configuration
    // ══════════════════════════════════════════════════════════════════

    public Tenant updateRaspBehavior(String licenseKey, RaspBehaviorUpdate update) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        tenant.setBlockOnRoot(update.blockOnRoot);
        tenant.setBlockOnFrida(update.blockOnFrida);
        tenant.setBlockOnDebugger(update.blockOnDebugger);
        tenant.setBlockOnEmulator(update.blockOnEmulator);
        tenant.setBlockOnHooked(update.blockOnHooked);
        tenant.setBlockOnTampered(update.blockOnTampered);
        tenant.setBlockOnUntrustedInstaller(update.blockOnUntrustedInstaller);

        log.info("Updated RASP behavior for tenant: {}", licenseKey);
        return tenantRepository.save(tenant);
    }

    // ══════════════════════════════════════════════════════════════════
    // Reaction Policy Configuration
    // ══════════════════════════════════════════════════════════════════

    public Tenant updateReactionPolicies(String licenseKey, ReactionPolicyUpdate update) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        if (update.rootDetectionReaction != null) {
            tenant.setRootDetectionReaction(update.rootDetectionReaction);
        }
        if (update.fridaDetectionReaction != null) {
            tenant.setFridaDetectionReaction(update.fridaDetectionReaction);
        }
        if (update.tamperedApkReaction != null) {
            tenant.setTamperedApkReaction(update.tamperedApkReaction);
        }
        if (update.malwareDetectionReaction != null) {
            tenant.setMalwareDetectionReaction(update.malwareDetectionReaction);
        }

        log.info("Updated reaction policies for tenant: {}", licenseKey);
        return tenantRepository.save(tenant);
    }

    // ══════════════════════════════════════════════════════════════════
    // SSL Certificate Pinning
    // ══════════════════════════════════════════════════════════════════

    public Tenant addSslCertificatePin(String licenseKey, String certificateHash) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        tenant.getSslCertificatePins().add(certificateHash);
        
        log.info("Added SSL certificate pin for tenant: {}", licenseKey);
        return tenantRepository.save(tenant);
    }

    public Tenant removeSslCertificatePin(String licenseKey, String certificateHash) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        tenant.getSslCertificatePins().remove(certificateHash);
        
        log.info("Removed SSL certificate pin for tenant: {}", licenseKey);
        return tenantRepository.save(tenant);
    }

    public Tenant updateAllSslCertificatePins(String licenseKey, Set<String> certificateHashes) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        tenant.setSslCertificatePins(certificateHashes);
        
        log.info("Updated all SSL certificate pins for tenant: {} (count: {})", 
            licenseKey, certificateHashes.size());
        return tenantRepository.save(tenant);
    }

    // ══════════════════════════════════════════════════════════════════
    // Whitelist Operations
    // ══════════════════════════════════════════════════════════════════

    public void addToWhitelist(String licenseKey, String packageName, String reason, String category) {
        TenantWhitelist whitelist = new TenantWhitelist();
        whitelist.setLicenseKey(licenseKey);
        whitelist.setPackageName(packageName);
        whitelist.setReason(reason);
        whitelist.setCategory(category);
        
        whitelistRepository.save(whitelist);
        log.info("Added to whitelist: {} for tenant: {}", packageName, licenseKey);
    }

    public void removeFromWhitelist(String licenseKey, String packageName) {
        whitelistRepository.deleteByLicenseKeyAndPackageName(licenseKey, packageName);
        log.info("Removed from whitelist: {} for tenant: {}", packageName, licenseKey);
    }

    public List<TenantWhitelist> getWhitelist(String licenseKey) {
        return whitelistRepository.findByLicenseKey(licenseKey);
    }

    // ══════════════════════════════════════════════════════════════════
    // Blacklist Operations
    // ══════════════════════════════════════════════════════════════════

    public void addToBlacklist(String licenseKey, String packageName, String reason, String category) {
        TenantBlacklist blacklist = new TenantBlacklist();
        blacklist.setLicenseKey(licenseKey);
        blacklist.setPackageName(packageName);
        blacklist.setReason(reason);
        blacklist.setCategory(category);
        
        blacklistRepository.save(blacklist);
        log.info("Added to blacklist: {} for tenant: {}", packageName, licenseKey);
    }

    public void removeFromBlacklist(String licenseKey, String packageName) {
        blacklistRepository.deleteByLicenseKeyAndPackageName(licenseKey, packageName);
        log.info("Removed from blacklist: {} for tenant: {}", packageName, licenseKey);
    }

    public List<TenantBlacklist> getBlacklist(String licenseKey) {
        return blacklistRepository.findByLicenseKey(licenseKey);
    }

    // ══════════════════════════════════════════════════════════════════
    // Sync Tracking
    // ══════════════════════════════════════════════════════════════════

    public void updateLastSync(String licenseKey) {
        Tenant tenant = getTenantByLicenseKey(licenseKey)
            .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + licenseKey));

        tenant.setLastSyncAt(LocalDateTime.now());
        tenantRepository.save(tenant);
    }

    // ══════════════════════════════════════════════════════════════════
    // DTOs
    // ══════════════════════════════════════════════════════════════════

    public static class RaspBehaviorUpdate {
        public boolean blockOnRoot = true;
        public boolean blockOnFrida = true;
        public boolean blockOnDebugger = false;
        public boolean blockOnEmulator = false;
        public boolean blockOnHooked = true;
        public boolean blockOnTampered = true;
        public boolean blockOnUntrustedInstaller = true;
    }

    public static class ReactionPolicyUpdate {
        public Tenant.ReactionPolicy rootDetectionReaction;
        public Tenant.ReactionPolicy fridaDetectionReaction;
        public Tenant.ReactionPolicy tamperedApkReaction;
        public Tenant.ReactionPolicy malwareDetectionReaction;
    }
}
