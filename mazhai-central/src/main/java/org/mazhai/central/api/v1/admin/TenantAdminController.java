package org.mazhai.central.api.v1.admin;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Tenant Administration API
 * Allows dashboard/admin users to manage client-specific whitelists and blacklists
 */
@RestController
@RequestMapping("/api/v1/admin/tenant")
@Validated
public class TenantAdminController {

    private static final Logger log = LoggerFactory.getLogger(TenantAdminController.class);

    /**
     * Add packages to tenant's whitelist (exceptions - will NOT be blocked)
     * 
     * POST /api/v1/admin/tenant/{license_key}/whitelist
     * Body: {"packages": ["com.teamviewer.quicksupport.market"], "reason": "Used for customer support"}
     */
    @PostMapping("/{license_key}/whitelist")
    public ResponseEntity<WhitelistResponse> addToWhitelist(
            @PathVariable("license_key") @NotBlank String licenseKey,
            @RequestBody @Valid WhitelistRequest request
    ) {
        log.info("Adding {} packages to whitelist for license={}", request.packages().size(), licenseKey);

        // TODO: Fetch or create TenantWhitelist entity
        // TODO: Add packages to malwareExceptions, smsForwarderExceptions, or remoteAccessExceptions
        // TODO: Save to database
        // TODO: Return updated whitelist

        WhitelistResponse response = new WhitelistResponse(
            licenseKey,
            request.packages(),
            "Whitelist updated successfully. Next SDK sync will apply changes.",
            System.currentTimeMillis()
        );

        log.info("Whitelist updated for license={}: {} packages", licenseKey, request.packages().size());
        return ResponseEntity.ok(response);
    }

    /**
     * Add packages to tenant's blacklist (custom threats to block)
     * 
     * POST /api/v1/admin/tenant/{license_key}/blacklist
     * Body: {"packages": ["com.competitor.bankapp"], "reason": "Block competitor app"}
     */
    @PostMapping("/{license_key}/blacklist")
    public ResponseEntity<BlacklistResponse> addToBlacklist(
            @PathVariable("license_key") @NotBlank String licenseKey,
            @RequestBody @Valid BlacklistRequest request
    ) {
        log.info("Adding {} packages to blacklist for license={}", request.packages().size(), licenseKey);

        // TODO: Fetch or create TenantBlacklist entity
        // TODO: Add packages to malwareAdditions, smsForwarderAdditions, or remoteAccessAdditions
        // TODO: Save to database
        // TODO: Return updated blacklist

        BlacklistResponse response = new BlacklistResponse(
            licenseKey,
            request.packages(),
            "Blacklist updated successfully. Next SDK sync will apply changes.",
            System.currentTimeMillis()
        );

        log.info("Blacklist updated for license={}: {} packages", licenseKey, request.packages().size());
        return ResponseEntity.ok(response);
    }

    /**
     * Remove packages from tenant's whitelist
     * 
     * DELETE /api/v1/admin/tenant/{license_key}/whitelist
     * Body: {"packages": ["com.teamviewer.quicksupport.market"]}
     */
    @DeleteMapping("/{license_key}/whitelist")
    public ResponseEntity<WhitelistResponse> removeFromWhitelist(
            @PathVariable("license_key") @NotBlank String licenseKey,
            @RequestBody @Valid RemovePackagesRequest request
    ) {
        log.info("Removing {} packages from whitelist for license={}", request.packages().size(), licenseKey);

        // TODO: Fetch TenantWhitelist entity
        // TODO: Remove packages from exceptions
        // TODO: Save to database

        WhitelistResponse response = new WhitelistResponse(
            licenseKey,
            request.packages(),
            "Packages removed from whitelist successfully.",
            System.currentTimeMillis()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Remove packages from tenant's blacklist
     * 
     * DELETE /api/v1/admin/tenant/{license_key}/blacklist
     * Body: {"packages": ["com.competitor.bankapp"]}
     */
    @DeleteMapping("/{license_key}/blacklist")
    public ResponseEntity<BlacklistResponse> removeFromBlacklist(
            @PathVariable("license_key") @NotBlank String licenseKey,
            @RequestBody @Valid RemovePackagesRequest request
    ) {
        log.info("Removing {} packages from blacklist for license={}", request.packages().size(), licenseKey);

        // TODO: Fetch TenantBlacklist entity
        // TODO: Remove packages from additions
        // TODO: Save to database

        BlacklistResponse response = new BlacklistResponse(
            licenseKey,
            request.packages(),
            "Packages removed from blacklist successfully.",
            System.currentTimeMillis()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Get tenant's current configuration (whitelist + blacklist)
     * 
     * GET /api/v1/admin/tenant/{license_key}/config
     */
    @GetMapping("/{license_key}/config")
    public ResponseEntity<TenantConfigResponse> getTenantConfig(
            @PathVariable("license_key") @NotBlank String licenseKey
    ) {
        log.info("Fetching tenant config for license={}", licenseKey);

        // TODO: Fetch TenantConfig, TenantWhitelist, TenantBlacklist from database
        // TODO: Return comprehensive view

        TenantConfigResponse response = new TenantConfigResponse(
            licenseKey,
            "Example Company",
            List.of("com.teamviewer.quicksupport.market"),  // whitelist
            List.of("com.competitor.bankapp"),  // blacklist
            true,  // isActive
            System.currentTimeMillis()
        );

        return ResponseEntity.ok(response);
    }

    // ══════════════════════════════════════════════════════════════════
    // Request/Response DTOs
    // ══════════════════════════════════════════════════════════════════

    public record WhitelistRequest(
        @NotEmpty(message = "Packages list cannot be empty")
        List<@NotBlank String> packages,
        
        String reason
    ) {}

    public record BlacklistRequest(
        @NotEmpty(message = "Packages list cannot be empty")
        List<@NotBlank String> packages,
        
        String reason
    ) {}

    public record RemovePackagesRequest(
        @NotEmpty(message = "Packages list cannot be empty")
        List<@NotBlank String> packages
    ) {}

    public record WhitelistResponse(
        String licenseKey,
        List<String> packages,
        String message,
        Long timestamp
    ) {}

    public record BlacklistResponse(
        String licenseKey,
        List<String> packages,
        String message,
        Long timestamp
    ) {}

    public record TenantConfigResponse(
        String licenseKey,
        String companyName,
        List<String> whitelistedPackages,
        List<String> blacklistedPackages,
        Boolean isActive,
        Long lastModified
    ) {}
}
