package org.mazhai.aran.telemetry.api;

import jakarta.validation.Valid;
import org.mazhai.aran.telemetry.service.TelemetryIngestService;
import org.mazhai.aran.telemetry.sse.TelemetrySseBroker;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/v1/telemetry")
public class TelemetryController {

    private final TelemetryIngestService telemetryIngestService;
    private final TelemetrySseBroker sseBroker;

    public TelemetryController(TelemetryIngestService telemetryIngestService,
                                TelemetrySseBroker sseBroker) {
        this.telemetryIngestService = telemetryIngestService;
        this.sseBroker = sseBroker;
    }

    @PostMapping("/ingest")
    public CompletableFuture<ResponseEntity<TelemetryIngestResponse>> ingest(
            @Valid @RequestBody TelemetryIngestRequest request
    ) {
        return telemetryIngestService.ingestAsync(request).thenApply(ResponseEntity::ok);
    }

    @PostMapping("/ingest/batch")
    public CompletableFuture<ResponseEntity<BatchIngestResponse>> ingestBatch(
            @RequestBody List<@Valid TelemetryIngestRequest> requests
    ) {
        var futures = requests.stream()
                .map(telemetryIngestService::ingestAsync)
                .toList();
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(v -> ResponseEntity.accepted().body(
                        new BatchIngestResponse("ACCEPTED", requests.size(), UUID.randomUUID().toString())
                ));
    }

    /**
     * SSE stream for SOC dashboard real-time threat feed.
     * GET /api/v1/telemetry/stream
     * Each verified ingest event is pushed as: event: threat\ndata: {json}\n\n
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return sseBroker.subscribe();
    }

    public record BatchIngestResponse(String status, int count, String batchId) {}
}
