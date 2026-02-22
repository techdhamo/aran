package org.mazhai.central.api.v1.telemetry;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record TelemetryPayload(
        @JsonProperty("device_fingerprint")
        @NotBlank
        String deviceFingerprint,

        @JsonProperty("app_id")
        @NotBlank
        String appId,

        @JsonProperty("timestamp")
        @NotBlank
        String timestamp,

        @JsonProperty("environment_state")
        @NotNull
        @Valid
        EnvironmentState environmentState,

        @JsonProperty("runtime_state")
        @NotNull
        @Valid
        RuntimeState runtimeState
) {

    public record EnvironmentState(
            @JsonProperty("is_rooted")
            @NotNull
            Boolean isRooted,

            @JsonProperty("root_indicators")
            @NotNull
            List<@NotBlank String> rootIndicators,

            @JsonProperty("is_emulator")
            @NotNull
            Boolean isEmulator,

            @JsonProperty("is_debugger_attached")
            @NotNull
            Boolean isDebuggerAttached
    ) {
    }

    public record RuntimeState(
            @JsonProperty("frida_detected")
            @NotNull
            Boolean fridaDetected,

            @JsonProperty("memory_hooks")
            @NotNull
            List<@NotBlank String> memoryHooks
    ) {
    }
}
