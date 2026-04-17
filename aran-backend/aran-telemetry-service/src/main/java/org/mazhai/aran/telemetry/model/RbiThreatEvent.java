package org.mazhai.aran.telemetry.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * RbiThreatEvent — Structured representation of a decrypted SDK telemetry payload.
 *
 * RBI/NPCI compliance notes:
 * - No PII fields (no IMEI, MSISDN, account numbers). device_fingerprint is a
 *   hardware-derived hash — the raw identifiers never leave the device.
 * - severity_level and threat_vector.categories allow backend risk-scoring without
 *   re-running RASP logic server-side.
 * - native_threat_mask provides raw bitmask for forensic correlation across events.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RbiThreatEvent(
        @JsonProperty("event_id")          String eventId,
        @JsonProperty("request_id")        String requestId,
        @JsonProperty("nonce")             String nonce,
        @JsonProperty("timestamp")         Long timestamp,
        @JsonProperty("severity_level")    String severityLevel,
        @JsonProperty("rasp_version")      String raspVersion,
        @JsonProperty("os_type")           String osType,
        @JsonProperty("native_threat_mask") String nativeThreatMask,
        @JsonProperty("threat_vector")     ThreatVector threatVector,
        @JsonProperty("device_context")    DeviceContext deviceContext
) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ThreatVector(
            List<String> categories,
            @JsonProperty("is_rooted")           boolean isRooted,
            @JsonProperty("frida_detected")      boolean fridaDetected,
            @JsonProperty("debugger_attached")   boolean debuggerAttached,
            @JsonProperty("emulator_detected")   boolean emulatorDetected,
            @JsonProperty("hook_detected")       boolean hookDetected,
            @JsonProperty("tampered")            boolean tampered,
            @JsonProperty("untrusted_installer") boolean untrustedInstaller,
            @JsonProperty("developer_mode")      boolean developerMode,
            @JsonProperty("adb_enabled")         boolean adbEnabled,
            @JsonProperty("env_tampering")       boolean envTampering,
            @JsonProperty("runtime_integrity")   boolean runtimeIntegrity,
            @JsonProperty("proxy_detected")      boolean proxyDetected,
            @JsonProperty("zygisk_detected")     boolean zygiskDetected,
            @JsonProperty("anon_elf_detected")   boolean anonElfDetected,
            @JsonProperty("zygisk_fd_detected")  boolean zygiskFdDetected,
            @JsonProperty("vpn_detected")        boolean vpnDetected,
            @JsonProperty("screen_recording")    boolean screenRecording,
            @JsonProperty("keylogger_risk")      boolean keyloggerRisk,
            @JsonProperty("untrusted_keyboard")  boolean untrustedKeyboard,
            @JsonProperty("device_lock_missing") boolean deviceLockMissing,
            @JsonProperty("overlay_detected")    boolean overlayDetected,
            @JsonProperty("unsecured_wifi")      boolean unsecuredWifi,
            @JsonProperty("time_spoofing")       boolean timeSpoofing,
            @JsonProperty("location_spoofing")   boolean locationSpoofing,
            @JsonProperty("screen_mirroring")    boolean screenMirroring,
            @JsonProperty("malware_count")       int malwareCount,
            @JsonProperty("sms_forwarder_count") int smsForwarderCount,
            @JsonProperty("remote_access_count") int remoteAccessCount
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DeviceContext(
            @JsonProperty("device_fingerprint") String deviceFingerprint,
            @JsonProperty("app_id")             String appId
    ) {}
}
