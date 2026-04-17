package org.mazhai.central.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Tenant-Specific Blacklist
 * Client-specific additions to the global threat lists
 */
@Entity
@Table(name = "tenant_blacklist")
public class TenantBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String licenseKey;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_malware_additions", joinColumns = @JoinColumn(name = "blacklist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> malwareAdditions = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_sms_forwarder_additions", joinColumns = @JoinColumn(name = "blacklist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> smsForwarderAdditions = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tenant_remote_access_additions", joinColumns = @JoinColumn(name = "blacklist_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> remoteAccessAdditions = new HashSet<>();

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant lastModified;

    @Column(length = 500)
    private String reason;

    // Constructors
    public TenantBlacklist() {
        this.createdAt = Instant.now();
        this.lastModified = Instant.now();
    }

    public TenantBlacklist(String licenseKey) {
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

    public Set<String> getMalwareAdditions() {
        return malwareAdditions;
    }

    public void setMalwareAdditions(Set<String> malwareAdditions) {
        this.malwareAdditions = malwareAdditions;
    }

    public Set<String> getSmsForwarderAdditions() {
        return smsForwarderAdditions;
    }

    public void setSmsForwarderAdditions(Set<String> smsForwarderAdditions) {
        this.smsForwarderAdditions = smsForwarderAdditions;
    }

    public Set<String> getRemoteAccessAdditions() {
        return remoteAccessAdditions;
    }

    public void setRemoteAccessAdditions(Set<String> remoteAccessAdditions) {
        this.remoteAccessAdditions = remoteAccessAdditions;
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
