package org.mazhai.central.domain;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Tenant Configuration
 * Stores client-specific preferences tied to a license key
 */
@Entity
@Table(name = "tenant_config")
public class TenantConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String licenseKey;

    @Column(nullable = false, length = 255)
    private String companyName;

    @Column(length = 100)
    private String contactEmail;

    @Column(nullable = false)
    private Boolean isActive = true;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant lastModified;

    // Security Policy Overrides (nullable = client uses global defaults)
    @Column
    private Boolean killOnRoot;

    @Column
    private Boolean killOnFrida;

    @Column
    private Boolean killOnDebugger;

    @Column
    private Boolean killOnEmulator;

    @Column
    private Boolean killOnHook;

    @Column
    private Boolean killOnTamper;

    @Column
    private Boolean killOnMalware;

    @Column
    private Boolean killOnProxy;

    @Column
    private Boolean killOnVpn;

    @Column(length = 1000)
    private String notes;

    // Constructors
    public TenantConfig() {
        this.createdAt = Instant.now();
        this.lastModified = Instant.now();
    }

    public TenantConfig(String licenseKey, String companyName) {
        this.licenseKey = licenseKey;
        this.companyName = companyName;
        this.createdAt = Instant.now();
        this.lastModified = Instant.now();
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

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public void setContactEmail(String contactEmail) {
        this.contactEmail = contactEmail;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getLastModified() {
        return lastModified;
    }

    public void setLastModified(Instant lastModified) {
        this.lastModified = lastModified;
    }

    public Boolean getKillOnRoot() {
        return killOnRoot;
    }

    public void setKillOnRoot(Boolean killOnRoot) {
        this.killOnRoot = killOnRoot;
    }

    public Boolean getKillOnFrida() {
        return killOnFrida;
    }

    public void setKillOnFrida(Boolean killOnFrida) {
        this.killOnFrida = killOnFrida;
    }

    public Boolean getKillOnDebugger() {
        return killOnDebugger;
    }

    public void setKillOnDebugger(Boolean killOnDebugger) {
        this.killOnDebugger = killOnDebugger;
    }

    public Boolean getKillOnEmulator() {
        return killOnEmulator;
    }

    public void setKillOnEmulator(Boolean killOnEmulator) {
        this.killOnEmulator = killOnEmulator;
    }

    public Boolean getKillOnHook() {
        return killOnHook;
    }

    public void setKillOnHook(Boolean killOnHook) {
        this.killOnHook = killOnHook;
    }

    public Boolean getKillOnTamper() {
        return killOnTamper;
    }

    public void setKillOnTamper(Boolean killOnTamper) {
        this.killOnTamper = killOnTamper;
    }

    public Boolean getKillOnMalware() {
        return killOnMalware;
    }

    public void setKillOnMalware(Boolean killOnMalware) {
        this.killOnMalware = killOnMalware;
    }

    public Boolean getKillOnProxy() {
        return killOnProxy;
    }

    public void setKillOnProxy(Boolean killOnProxy) {
        this.killOnProxy = killOnProxy;
    }

    public Boolean getKillOnVpn() {
        return killOnVpn;
    }

    public void setKillOnVpn(Boolean killOnVpn) {
        this.killOnVpn = killOnVpn;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}
