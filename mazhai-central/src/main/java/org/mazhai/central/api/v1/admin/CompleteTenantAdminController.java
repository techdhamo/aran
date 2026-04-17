package org.mazhai.central.api.v1.admin;

import org.mazhai.central.domain.Tenant;
import org.mazhai.central.domain.TenantBlacklist;
import org.mazhai.central.domain.TenantWhitelist;
import org.mazhai.central.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Complete Tenant Admin Controller
 * 
 * Full CRUD operations for tenant management including:
 * - Tenant creation and configuration
 * - RASP behavior policies
 * - Reaction policies for security events
 * - Whitelist/Blacklist management
 * - SSL certificate pinning
 * 
 * Admin API - Requires authentication (TODO: Add @PreAuthorize)
 */
@RestController
@RequestMapping("/api/v1/admin/tenants")
public class CompleteTenantAdminController {

    private static final Logger log = LoggerFactory.getLogger(CompleteTenantAdminController.class);

    private final TenantService tenantService;

    public CompleteTenantAdminController(TenantService tenantService) {
        this.tenantService = tenantService;
    }

    // ══════════════════════════════════════════════════════════════════
    // Tenant CRUD Operations
    // ══════════════════════════════════════════════════════════════════

    /**
     * Create new tenant
     * POST /api/v1/admin/tenants
     */
    @PostMapping
    public ResponseEntity<TenantResponse> createTenant(@RequestBody CreateTenantRequest request) {
        log.info("Creating tenant: {}", request.organizationName);

        Tenant tenant = new Tenant(request.licenseKey, request.organizationName);
        tenant.setContactEmail(request.contactEmail);
        tenant.setContactPhone(request.contactPhone);
        tenant.setTier(request.tier != null ? request.tier : Tenant.TenantTier.STANDARD);
        tenant.setMaxDevices(request.maxDevices != null ? request.maxDevices : 1000);
        tenant.setApiBaseUrl(request.apiBaseUrl);

        Tenant created = tenantService.createTenant(tenant);
        return ResponseEntity.ok(TenantResponse.from(created));
    }

    /**
     * Get all tenants
     * GET /api/v1/admin/tenants
     */
    @GetMapping
    public ResponseEntity<List<TenantResponse>> getAllTenants() {
        List<Tenant> tenants = tenantService.getAllTenants();
        return ResponseEntity.ok(tenants.stream().map(TenantResponse::from).toList());
    }

    /**
     * Get tenant by license key
     * GET /api/v1/admin/tenants/{licenseKey}
     */
    @GetMapping("/{licenseKey}")
    public ResponseEntity<TenantResponse> getTenant(@PathVariable String licenseKey) {
        return tenantService.getTenantByLicenseKey(licenseKey)
            .map(TenantResponse::from)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Update tenant basic info
     * PUT /api/v1/admin/tenants/{id}
     */
    @PutMapping("/{id}")
    public ResponseEntity<TenantResponse> updateTenant(
        @PathVariable Long id,
        @RequestBody UpdateTenantRequest request
    ) {
        Tenant update = new Tenant();
        update.setOrganizationName(request.organizationName);
        update.setContactEmail(request.contactEmail);
        update.setContactPhone(request.contactPhone);
        update.setStatus(request.status);
        update.setTier(request.tier);
        update.setMaxDevices(request.maxDevices);

        Tenant updated = tenantService.updateTenant(id, update);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    /**
     * Delete tenant
     * DELETE /api/v1/admin/tenants/{id}
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteTenant(@PathVariable Long id) {
        tenantService.deleteTenant(id);
        return ResponseEntity.noContent().build();
    }

    // ══════════════════════════════════════════════════════════════════
    // RASP Behavior Configuration
    // ══════════════════════════════════════════════════════════════════

    /**
     * Update RASP blocking behavior
     * PUT /api/v1/admin/tenants/{licenseKey}/rasp-behavior
     */
    @PutMapping("/{licenseKey}/rasp-behavior")
    public ResponseEntity<TenantResponse> updateRaspBehavior(
        @PathVariable String licenseKey,
        @RequestBody RaspBehaviorRequest request
    ) {
        log.info("Updating RASP behavior for tenant: {}", licenseKey);

        TenantService.RaspBehaviorUpdate update = new TenantService.RaspBehaviorUpdate();
        update.blockOnRoot = request.blockOnRoot;
        update.blockOnFrida = request.blockOnFrida;
        update.blockOnDebugger = request.blockOnDebugger;
        update.blockOnEmulator = request.blockOnEmulator;
        update.blockOnHooked = request.blockOnHooked;
        update.blockOnTampered = request.blockOnTampered;
        update.blockOnUntrustedInstaller = request.blockOnUntrustedInstaller;

        Tenant updated = tenantService.updateRaspBehavior(licenseKey, update);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    // ══════════════════════════════════════════════════════════════════
    // Reaction Policy Configuration
    // ══════════════════════════════════════════════════════════════════

    /**
     * Update reaction policies for security events
     * PUT /api/v1/admin/tenants/{licenseKey}/reaction-policies
     * 
     * Reaction policies determine what happens when threats are detected:
     * - LOG_ONLY: Just log, allow app to continue
     * - WARN_USER: Show warning dialog
     * - BLOCK_API: Block API calls but allow app
     * - KILL_APP: Terminate immediately
     * - BLOCK_AND_REPORT: Block + send telemetry
     */
    @PutMapping("/{licenseKey}/reaction-policies")
    public ResponseEntity<TenantResponse> updateReactionPolicies(
        @PathVariable String licenseKey,
        @RequestBody ReactionPolicyRequest request
    ) {
        log.info("Updating reaction policies for tenant: {}", licenseKey);

        TenantService.ReactionPolicyUpdate update = new TenantService.ReactionPolicyUpdate();
        update.rootDetectionReaction = request.rootDetectionReaction;
        update.fridaDetectionReaction = request.fridaDetectionReaction;
        update.tamperedApkReaction = request.tamperedApkReaction;
        update.malwareDetectionReaction = request.malwareDetectionReaction;

        Tenant updated = tenantService.updateReactionPolicies(licenseKey, update);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    // ══════════════════════════════════════════════════════════════════
    // SSL Certificate Pinning
    // ══════════════════════════════════════════════════════════════════

    /**
     * Add SSL certificate pin
     * POST /api/v1/admin/tenants/{licenseKey}/ssl-pins
     */
    @PostMapping("/{licenseKey}/ssl-pins")
    public ResponseEntity<TenantResponse> addSslPin(
        @PathVariable String licenseKey,
        @RequestBody SslPinRequest request
    ) {
        log.info("Adding SSL pin for tenant: {}", licenseKey);
        Tenant updated = tenantService.addSslCertificatePin(licenseKey, request.certificateHash);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    /**
     * Remove SSL certificate pin
     * DELETE /api/v1/admin/tenants/{licenseKey}/ssl-pins/{hash}
     */
    @DeleteMapping("/{licenseKey}/ssl-pins/{hash}")
    public ResponseEntity<TenantResponse> removeSslPin(
        @PathVariable String licenseKey,
        @PathVariable String hash
    ) {
        log.info("Removing SSL pin for tenant: {}", licenseKey);
        Tenant updated = tenantService.removeSslCertificatePin(licenseKey, hash);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    /**
     * Update all SSL certificate pins
     * PUT /api/v1/admin/tenants/{licenseKey}/ssl-pins
     */
    @PutMapping("/{licenseKey}/ssl-pins")
    public ResponseEntity<TenantResponse> updateAllSslPins(
        @PathVariable String licenseKey,
        @RequestBody SslPinsRequest request
    ) {
        log.info("Updating all SSL pins for tenant: {} (count: {})", 
            licenseKey, request.certificateHashes.size());
        Tenant updated = tenantService.updateAllSslCertificatePins(licenseKey, request.certificateHashes);
        return ResponseEntity.ok(TenantResponse.from(updated));
    }

    // ══════════════════════════════════════════════════════════════════
    // Whitelist Management
    // ══════════════════════════════════════════════════════════════════

    /**
     * Get whitelist
     * GET /api/v1/admin/tenants/{licenseKey}/whitelist
     */
    @GetMapping("/{licenseKey}/whitelist")
    public ResponseEntity<List<TenantWhitelist>> getWhitelist(@PathVariable String licenseKey) {
        return ResponseEntity.ok(tenantService.getWhitelist(licenseKey));
    }

    /**
     * Add to whitelist
     * POST /api/v1/admin/tenants/{licenseKey}/whitelist
     */
    @PostMapping("/{licenseKey}/whitelist")
    public ResponseEntity<Map<String, String>> addToWhitelist(
        @PathVariable String licenseKey,
        @RequestBody WhitelistRequest request
    ) {
        log.info("Adding to whitelist: {} for tenant: {}", request.packageName, licenseKey);
        tenantService.addToWhitelist(licenseKey, request.packageName, request.reason, request.category);
        return ResponseEntity.ok(Map.of("status", "added", "package", request.packageName));
    }

    /**
     * Remove from whitelist
     * DELETE /api/v1/admin/tenants/{licenseKey}/whitelist/{packageName}
     */
    @DeleteMapping("/{licenseKey}/whitelist/{packageName}")
    public ResponseEntity<Map<String, String>> removeFromWhitelist(
        @PathVariable String licenseKey,
        @PathVariable String packageName
    ) {
        log.info("Removing from whitelist: {} for tenant: {}", packageName, licenseKey);
        tenantService.removeFromWhitelist(licenseKey, packageName);
        return ResponseEntity.ok(Map.of("status", "removed", "package", packageName));
    }

    // ══════════════════════════════════════════════════════════════════
    // Blacklist Management
    // ══════════════════════════════════════════════════════════════════

    /**
     * Get blacklist
     * GET /api/v1/admin/tenants/{licenseKey}/blacklist
     */
    @GetMapping("/{licenseKey}/blacklist")
    public ResponseEntity<List<TenantBlacklist>> getBlacklist(@PathVariable String licenseKey) {
        return ResponseEntity.ok(tenantService.getBlacklist(licenseKey));
    }

    /**
     * Add to blacklist
     * POST /api/v1/admin/tenants/{licenseKey}/blacklist
     */
    @PostMapping("/{licenseKey}/blacklist")
    public ResponseEntity<Map<String, String>> addToBlacklist(
        @PathVariable String licenseKey,
        @RequestBody BlacklistRequest request
    ) {
        log.info("Adding to blacklist: {} for tenant: {}", request.packageName, licenseKey);
        tenantService.addToBlacklist(licenseKey, request.packageName, request.reason, request.category);
        return ResponseEntity.ok(Map.of("status", "added", "package", request.packageName));
    }

    /**
     * Remove from blacklist
     * DELETE /api/v1/admin/tenants/{licenseKey}/blacklist/{packageName}
     */
    @DeleteMapping("/{licenseKey}/blacklist/{packageName}")
    public ResponseEntity<Map<String, String>> removeFromBlacklist(
        @PathVariable String licenseKey,
        @PathVariable String packageName
    ) {
        log.info("Removing from blacklist: {} for tenant: {}", packageName, licenseKey);
        tenantService.removeFromBlacklist(licenseKey, packageName);
        return ResponseEntity.ok(Map.of("status", "removed", "package", packageName));
    }

    // ══════════════════════════════════════════════════════════════════
    // DTOs
    // ══════════════════════════════════════════════════════════════════

    public record CreateTenantRequest(
        String licenseKey,
        String organizationName,
        String contactEmail,
        String contactPhone,
        Tenant.TenantTier tier,
        Integer maxDevices,
        String apiBaseUrl
    ) {}

    public record UpdateTenantRequest(
        String organizationName,
        String contactEmail,
        String contactPhone,
        Tenant.TenantStatus status,
        Tenant.TenantTier tier,
        Integer maxDevices
    ) {}

    public record RaspBehaviorRequest(
        boolean blockOnRoot,
        boolean blockOnFrida,
        boolean blockOnDebugger,
        boolean blockOnEmulator,
        boolean blockOnHooked,
        boolean blockOnTampered,
        boolean blockOnUntrustedInstaller
    ) {}

    public record ReactionPolicyRequest(
        Tenant.ReactionPolicy rootDetectionReaction,
        Tenant.ReactionPolicy fridaDetectionReaction,
        Tenant.ReactionPolicy tamperedApkReaction,
        Tenant.ReactionPolicy malwareDetectionReaction
    ) {}

    public record SslPinRequest(String certificateHash) {}

    public record SslPinsRequest(Set<String> certificateHashes) {}

    public record WhitelistRequest(
        String packageName,
        String reason,
        String category
    ) {}

    public record BlacklistRequest(
        String packageName,
        String reason,
        String category
    ) {}

    public record TenantResponse(
        Long id,
        String licenseKey,
        String organizationName,
        String contactEmail,
        String contactPhone,
        Tenant.TenantStatus status,
        Tenant.TenantTier tier,
        RaspBehavior raspBehavior,
        ReactionPolicies reactionPolicies,
        Set<String> sslCertificatePins,
        String apiBaseUrl,
        Integer maxDevices,
        Integer currentDevices,
        String createdAt,
        String updatedAt,
        String lastSyncAt
    ) {
        public static TenantResponse from(Tenant tenant) {
            return new TenantResponse(
                tenant.getId(),
                tenant.getLicenseKey(),
                tenant.getOrganizationName(),
                tenant.getContactEmail(),
                tenant.getContactPhone(),
                tenant.getStatus(),
                tenant.getTier(),
                new RaspBehavior(
                    tenant.isBlockOnRoot(),
                    tenant.isBlockOnFrida(),
                    tenant.isBlockOnDebugger(),
                    tenant.isBlockOnEmulator(),
                    tenant.isBlockOnHooked(),
                    tenant.isBlockOnTampered(),
                    tenant.isBlockOnUntrustedInstaller()
                ),
                new ReactionPolicies(
                    tenant.getRootDetectionReaction(),
                    tenant.getFridaDetectionReaction(),
                    tenant.getTamperedApkReaction(),
                    tenant.getMalwareDetectionReaction()
                ),
                tenant.getSslCertificatePins(),
                tenant.getApiBaseUrl(),
                tenant.getMaxDevices(),
                tenant.getCurrentDevices(),
                tenant.getCreatedAt() != null ? tenant.getCreatedAt().toString() : null,
                tenant.getUpdatedAt() != null ? tenant.getUpdatedAt().toString() : null,
                tenant.getLastSyncAt() != null ? tenant.getLastSyncAt().toString() : null
            );
        }
    }

    public record RaspBehavior(
        boolean blockOnRoot,
        boolean blockOnFrida,
        boolean blockOnDebugger,
        boolean blockOnEmulator,
        boolean blockOnHooked,
        boolean blockOnTampered,
        boolean blockOnUntrustedInstaller
    ) {}

    public record ReactionPolicies(
        Tenant.ReactionPolicy rootDetectionReaction,
        Tenant.ReactionPolicy fridaDetectionReaction,
        Tenant.ReactionPolicy tamperedApkReaction,
        Tenant.ReactionPolicy malwareDetectionReaction
    ) {}
}
