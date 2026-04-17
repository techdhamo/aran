package org.mazhai.central.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Tenant-Specific Whitelist
 * Client-specific exceptions (apps or pins that should NEVER be blocked for this client)
 */
@Entity
@Table(name = "tenant_whitelist")
public class TenantWhitelist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String licenseKey;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_malware_exceptions", joinColumns = @JoinColumn(name = "whitelist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> malwareExceptions = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_sms_forwarder_exceptions", joinColumns = @JoinColumn(name = "whitelist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> smsForwarderExceptions = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_remote_access_exceptions", joinColumns = @JoinColumn(name = "whitelist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> remoteAccessExceptions = new HashSet<>();

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant lastModified;

    @Column(length = 500)
    private String reason;

    // Constructors
    public TenantWhitelist() {
        this.createdAt = Instant.now();
        this.lastModified = Instant.now();
    }

    public TenantWhitelist(String licenseKey) {
        this.licenseKey = licenseKey;
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

    public Set<String> getMalwareExceptions() {
        return malwareExceptions;
    }

    public void setMalwareExceptions(Set<String> malwareExceptions) {
        this.malwareExceptions = malwareExceptions;
    }

    public Set<String> getSmsForwarderExceptions() {
        return smsForwarderExceptions;
    }

    public void setSmsForwarderExceptions(Set<String> smsForwarderExceptions) {
        this.smsForwarderExceptions = smsForwarderExceptions;
    }

    public Set<String> getRemoteAccessExceptions() {
        return remoteAccessExceptions;
    }

    public void setRemoteAccessExceptions(Set<String> remoteAccessExceptions) {
        this.remoteAccessExceptions = remoteAccessExceptions;
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

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
