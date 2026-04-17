package org.mazhai.central.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Tenant Entity - Multi-Tenant SaaS Configuration
 * 
 * Represents a customer organization (e.g., Bank A, Bank B)
 * with their specific RASP configuration, security policies,
 * and behavior/reaction rules.
 */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String licenseKey;

    @Column(nullable = false, length = 200)
    private String organizationName;

    @Column(length = 100)
    private String contactEmail;

    @Column(length = 20)
    private String contactPhone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TenantStatus status = TenantStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TenantTier tier = TenantTier.STANDARD;

    // RASP Behavior Configuration
    @Column(nullable = false)
    private boolean blockOnRoot = true;

    @Column(nullable = false)
    private boolean blockOnFrida = true;

    @Column(nullable = false)
    private boolean blockOnDebugger = false; // Allow in dev

    @Column(nullable = false)
    private boolean blockOnEmulator = false; // Allow in dev

    @Column(nullable = false)
    private boolean blockOnHooked = true;

    @Column(nullable = false)
    private boolean blockOnTampered = true;

    @Column(nullable = false)
    private boolean blockOnUntrustedInstaller = true;

    // Reaction Policies
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReactionPolicy rootDetectionReaction = ReactionPolicy.BLOCK_API;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReactionPolicy fridaDetectionReaction = ReactionPolicy.BLOCK_API;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReactionPolicy tamperedApkReaction = ReactionPolicy.KILL_APP;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReactionPolicy malwareDetectionReaction = ReactionPolicy.KILL_APP;

    // SSL Certificate Pinning
    @ElementCollection
    @CollectionTable(name = "tenant_ssl_pins", joinColumns = @JoinColumn(name = "tenant_id"))
    @Column(name = "certificate_hash", length = 64)
    private Set<String> sslCertificatePins = new HashSet<>();

    @Column(length = 500)
    private String apiBaseUrl;

    // Metadata
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Column
    private LocalDateTime lastSyncAt;

    @Column(nullable = false)
    private int maxDevices = 1000;

    @Column(nullable = false)
    private int currentDevices = 0;

    // Constructors
    public Tenant() {}

    public Tenant(String licenseKey, String organizationName) {
        this.licenseKey = licenseKey;
        this.organizationName = organizationName;
    }

    // Lifecycle callbacks
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getLicenseKey() {
        return licenseKey;
    }

    public void setLicenseKey(String licenseKey) {
        this.licenseKey = licenseKey;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public void setContactEmail(String contactEmail) {
        this.contactEmail = contactEmail;
    }

    public String getContactPhone() {
        return contactPhone;
    }

    public void setContactPhone(String contactPhone) {
        this.contactPhone = contactPhone;
    }

    public TenantStatus getStatus() {
        return status;
    }

    public void setStatus(TenantStatus status) {
        this.status = status;
    }

    public TenantTier getTier() {
        return tier;
    }

    public void setTier(TenantTier tier) {
        this.tier = tier;
    }

    public boolean isBlockOnRoot() {
        return blockOnRoot;
    }

    public void setBlockOnRoot(boolean blockOnRoot) {
        this.blockOnRoot = blockOnRoot;
    }

    public boolean isBlockOnFrida() {
        return blockOnFrida;
    }

    public void setBlockOnFrida(boolean blockOnFrida) {
        this.blockOnFrida = blockOnFrida;
    }

    public boolean isBlockOnDebugger() {
        return blockOnDebugger;
    }

    public void setBlockOnDebugger(boolean blockOnDebugger) {
        this.blockOnDebugger = blockOnDebugger;
    }

    public boolean isBlockOnEmulator() {
        return blockOnEmulator;
    }

    public void setBlockOnEmulator(boolean blockOnEmulator) {
        this.blockOnEmulator = blockOnEmulator;
    }

    public boolean isBlockOnHooked() {
        return blockOnHooked;
    }

    public void setBlockOnHooked(boolean blockOnHooked) {
        this.blockOnHooked = blockOnHooked;
    }

    public boolean isBlockOnTampered() {
        return blockOnTampered;
    }

    public void setBlockOnTampered(boolean blockOnTampered) {
        this.blockOnTampered = blockOnTampered;
    }

    public boolean isBlockOnUntrustedInstaller() {
        return blockOnUntrustedInstaller;
    }

    public void setBlockOnUntrustedInstaller(boolean blockOnUntrustedInstaller) {
        this.blockOnUntrustedInstaller = blockOnUntrustedInstaller;
    }

    public ReactionPolicy getRootDetectionReaction() {
        return rootDetectionReaction;
    }

    public void setRootDetectionReaction(ReactionPolicy rootDetectionReaction) {
        this.rootDetectionReaction = rootDetectionReaction;
    }

    public ReactionPolicy getFridaDetectionReaction() {
        return fridaDetectionReaction;
    }

    public void setFridaDetectionReaction(ReactionPolicy fridaDetectionReaction) {
        this.fridaDetectionReaction = fridaDetectionReaction;
    }

    public ReactionPolicy getTamperedApkReaction() {
        return tamperedApkReaction;
    }

    public void setTamperedApkReaction(ReactionPolicy tamperedApkReaction) {
        this.tamperedApkReaction = tamperedApkReaction;
    }

    public ReactionPolicy getMalwareDetectionReaction() {
        return malwareDetectionReaction;
    }

    public void setMalwareDetectionReaction(ReactionPolicy malwareDetectionReaction) {
        this.malwareDetectionReaction = malwareDetectionReaction;
    }

    public Set<String> getSslCertificatePins() {
        return sslCertificatePins;
    }

    public void setSslCertificatePins(Set<String> sslCertificatePins) {
        this.sslCertificatePins = sslCertificatePins;
    }

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    public void setApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public LocalDateTime getLastSyncAt() {
        return lastSyncAt;
    }

    public void setLastSyncAt(LocalDateTime lastSyncAt) {
        this.lastSyncAt = lastSyncAt;
    }

    public int getMaxDevices() {
        return maxDevices;
    }

    public void setMaxDevices(int maxDevices) {
        this.maxDevices = maxDevices;
    }

    public int getCurrentDevices() {
        return currentDevices;
    }

    public void setCurrentDevices(int currentDevices) {
        this.currentDevices = currentDevices;
    }

    // Enums
    public enum TenantStatus {
        ACTIVE,
        SUSPENDED,
        TRIAL,
        EXPIRED
    }

    public enum TenantTier {
        TRIAL,
        STANDARD,
        PREMIUM,
        ENTERPRISE
    }

    public enum ReactionPolicy {
        LOG_ONLY,          // Just log the event, allow app to continue
        WARN_USER,         // Show warning dialog to user
        BLOCK_API,         // Block API calls but allow app to run
        KILL_APP,          // Terminate the application immediately
        BLOCK_AND_REPORT,  // Block + send detailed telemetry
        CUSTOM             // Delegate to host app (Native callback + Hybrid broadcast)
    }
}
