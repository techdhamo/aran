package org.mazhai.central.api.v1.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Cloud-Managed RASP Configuration Response
 * Supports both Android and iOS with OS-specific threat intelligence
 */
public record RaspConfigResponse(
        @JsonProperty("config_version")
        @NotBlank
        String configVersion,

        @JsonProperty("os_type")
        @NotBlank
        String osType,

        @JsonProperty("malware_packages")
        @NotNull
        List<String> malwarePackages,

        @JsonProperty("sms_forwarders")
        @NotNull
        List<String> smsForwarders,

        @JsonProperty("remote_access_apps")
        @NotNull
        List<String> remoteAccessApps,

        @JsonProperty("ssl_pins")
        @NotNull
        List<String> sslPins,

        @JsonProperty("active_policy")
        @NotNull
        ActivePolicy activePolicy,

        @JsonProperty("sync_interval_seconds")
        @NotNull
        Integer syncIntervalSeconds,

        @JsonProperty("tls_pins_blinded")
        List<TlsPinBlinded> tlsPinsBlinded,

        @JsonProperty("default_reaction_policy")
        Integer defaultReactionPolicy
) {

    /**
     * Blinded TLS pin for zero-knowledge certificate pinning.
     * SDK blinds incoming cert hash with salt and compares against these
     * WITHOUT ever decrypting the expected pin into plaintext RAM.
     */
    public record TlsPinBlinded(
            @JsonProperty("blinded")
            String blinded,

            @JsonProperty("host")
            String host
    ) {
    }

    public record ActivePolicy(
            @JsonProperty("kill_on_root")
            @NotNull
            Boolean killOnRoot,

            @JsonProperty("kill_on_frida")
            @NotNull
            Boolean killOnFrida,

            @JsonProperty("kill_on_debugger")
            @NotNull
            Boolean killOnDebugger,

            @JsonProperty("kill_on_emulator")
            @NotNull
            Boolean killOnEmulator,

            @JsonProperty("kill_on_hook")
            @NotNull
            Boolean killOnHook,

            @JsonProperty("kill_on_tamper")
            @NotNull
            Boolean killOnTamper,

            @JsonProperty("kill_on_untrusted_installer")
            @NotNull
            Boolean killOnUntrustedInstaller,

            @JsonProperty("kill_on_developer_mode")
            @NotNull
            Boolean killOnDeveloperMode,

            @JsonProperty("kill_on_adb_enabled")
            @NotNull
            Boolean killOnAdbEnabled,

            @JsonProperty("kill_on_proxy")
            @NotNull
            Boolean killOnProxy,

            @JsonProperty("kill_on_vpn")
            @NotNull
            Boolean killOnVpn,

            @JsonProperty("kill_on_malware")
            @NotNull
            Boolean killOnMalware
    ) {
    }
}
