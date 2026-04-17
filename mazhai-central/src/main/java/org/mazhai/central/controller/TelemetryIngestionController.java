package org.mazhai.central.controller;

import jakarta.validation.Valid;
import org.mazhai.central.dto.TelemetryPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TelemetryIngestionController {

    private static final Logger log = LoggerFactory.getLogger(TelemetryIngestionController.class);

    @PostMapping("/api/v1/telemetry/ingest")
    public ResponseEntity<Void> ingest(@Valid @RequestBody TelemetryPayload payload) {
        log.info("Loom-Check isVirtual: {}", Thread.currentThread().isVirtual());
        log.info(
                "signals appId={} deviceFingerprint={} rooted={} fridaDetected={} debuggerAttached={} ",
                payload.appId(),
                payload.deviceFingerprint(),
                payload.isRooted(),
                payload.fridaDetected(),
                payload.debuggerAttached()
        );
        return ResponseEntity.accepted().build();
    }
}
