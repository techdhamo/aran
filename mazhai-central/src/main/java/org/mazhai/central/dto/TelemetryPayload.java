package org.mazhai.central.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.constraints.NotBlank;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record TelemetryPayload(
        @NotBlank String deviceFingerprint,
        @NotBlank String appId,
        boolean isRooted
) {
}
