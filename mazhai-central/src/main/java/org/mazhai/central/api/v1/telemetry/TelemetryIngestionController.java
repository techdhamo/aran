package org.mazhai.central.api.v1.telemetry;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/telemetry")
@Validated
public class TelemetryIngestionController {

    private static final Logger log = LoggerFactory.getLogger(TelemetryIngestionController.class);

    @PostMapping("/ingest")
    public ResponseEntity<Void> ingest(@RequestBody @NotNull @Valid TelemetryPayload payload) {
        log.info("Telemetry payload received: {}", payload);
        return ResponseEntity.accepted().build();
    }
}
