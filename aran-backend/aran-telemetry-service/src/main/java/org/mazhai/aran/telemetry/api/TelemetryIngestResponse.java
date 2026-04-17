package org.mazhai.aran.telemetry.api;

public record TelemetryIngestResponse(
        String status,
        String correlationId
) {
}
