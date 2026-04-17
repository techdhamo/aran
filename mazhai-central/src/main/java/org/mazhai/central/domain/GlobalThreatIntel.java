package org.mazhai.central.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Global Threat Intelligence Database
 * Aran's baseline threat lists maintained by the security research team
 */
@Entity
@Table(name = "global_threat_intel")
public class GlobalThreatIntel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 20)
    private String osType; // "android" or "ios"

    @Column(nullable = false, length = 20)
    private String version; // e.g., "v1.1.0"

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "global_malware_packages", joinColumns = @JoinColumn(name = "intel_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> malwarePackages = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "global_sms_forwarders", joinColumns = @JoinColumn(name = "intel_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> smsForwarders = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "global_remote_access_apps", joinColumns = @JoinColumn(name = "intel_id"))
    @Column(name = "package_name", length = 255)
    private Set<String> remoteAccessApps = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "global_ssl_pins", joinColumns = @JoinColumn(name = "intel_id"))
    @Column(name = "pin_hash", length = 100)
    private Set<String> sslPins = new HashSet<>();

    @Column(nullable = false)
    private Instant lastUpdated;

    @Column(length = 500)
    private String updateNotes;

    // Constructors
    public GlobalThreatIntel() {
        this.lastUpdated = Instant.now();
    }

    public GlobalThreatIntel(String osType, String version) {
        this.osType = osType;
        this.version = version;
        this.lastUpdated = Instant.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getOsType() {
        return osType;
    }

    public void setOsType(String osType) {
        this.osType = osType;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Set<String> getMalwarePackages() {
        return malwarePackages;
    }

    public void setMalwarePackages(Set<String> malwarePackages) {
        this.malwarePackages = malwarePackages;
    }

    public Set<String> getSmsForwarders() {
        return smsForwarders;
    }

    public void setSmsForwarders(Set<String> smsForwarders) {
        this.smsForwarders = smsForwarders;
    }

    public Set<String> getRemoteAccessApps() {
        return remoteAccessApps;
    }

    public void setRemoteAccessApps(Set<String> remoteAccessApps) {
        this.remoteAccessApps = remoteAccessApps;
    }

    public Set<String> getSslPins() {
        return sslPins;
    }

    public void setSslPins(Set<String> sslPins) {
        this.sslPins = sslPins;
    }

    public Instant getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(Instant lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public String getUpdateNotes() {
        return updateNotes;
    }

    public void setUpdateNotes(String updateNotes) {
        this.updateNotes = updateNotes;
    }
}
