package org.mazhai.aran.telemetry.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.mazhai.aran.telemetry.api.TelemetryIngestRequest;
import org.mazhai.aran.telemetry.api.TelemetryIngestResponse;
import org.mazhai.aran.telemetry.crypto.TelemetryCryptoService;
import org.mazhai.aran.telemetry.crypto.TelemetryDecryptionException;
import org.mazhai.aran.telemetry.model.RbiThreatEvent;
import org.mazhai.aran.telemetry.sse.TelemetrySseBroker;
import org.mazhai.aran.telemetry.sse.TelemetrySseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

@Service
public class TelemetryIngestService {

    private static final Logger log = LoggerFactory.getLogger(TelemetryIngestService.class);

    private static final long MAX_CLOCK_SKEW_MS = 5 * 60 * 1000L;
    private static final int  NONCE_CACHE_SIZE  = 10_000;

    private final ExecutorService telemetryExecutor;
    private final TelemetryCryptoService cryptoService;
    private final TelemetrySseBroker sseBroker;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, Long> nonceCache = Collections.synchronizedMap(
        new LinkedHashMap<>(NONCE_CACHE_SIZE, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return size() > NONCE_CACHE_SIZE;
            }
        }
    );

    public TelemetryIngestService(ExecutorService telemetryExecutor,
                                   TelemetryCryptoService cryptoService,
                                   TelemetrySseBroker sseBroker) {
        this.telemetryExecutor = telemetryExecutor;
        this.cryptoService = cryptoService;
        this.sseBroker = sseBroker;
    }

    public CompletableFuture<TelemetryIngestResponse> ingestAsync(TelemetryIngestRequest request) {
        return CompletableFuture.supplyAsync(() -> processEvent(request), telemetryExecutor);
    }

    private TelemetryIngestResponse processEvent(TelemetryIngestRequest request) {
        String correlationId = UUID.randomUUID().toString();

        // 1. Replay protection: timestamp window
        long now = Instant.now().toEpochMilli();
        if (request.timestamp() == null || Math.abs(now - request.timestamp()) > MAX_CLOCK_SKEW_MS) {
            log.warn("[{}] Telemetry rejected: timestamp out of window ({})", correlationId, request.timestamp());
            return new TelemetryIngestResponse("REJECTED_REPLAY", correlationId);
        }

        // 2. Replay protection: nonce uniqueness
        if (request.nonce() == null || nonceCache.putIfAbsent(request.nonce(), now) != null) {
            log.warn("[{}] Telemetry rejected: nonce reuse ({})", correlationId, request.nonce());
            return new TelemetryIngestResponse("REJECTED_REPLAY", correlationId);
        }

        // 3. Schema version guard
        if (!"2.0".equals(request.schemaVersion())) {
            log.warn("[{}] Telemetry rejected: unsupported schema version ({})", correlationId, request.schemaVersion());
            return new TelemetryIngestResponse("REJECTED_SCHEMA", correlationId);
        }

        // 4. Asymmetric decryption
        String plaintext;
        try {
            plaintext = cryptoService.decrypt(request.encryptedBlob());
        } catch (TelemetryDecryptionException e) {
            log.error("[{}] Telemetry decryption failed", correlationId, e);
            return new TelemetryIngestResponse("REJECTED_DECRYPT", correlationId);
        }

        // 5. Payload integrity check (SHA-256)
        if (!cryptoService.verifyPayloadIntegrity(plaintext, request.payloadSha256())) {
            log.warn("[{}] Telemetry rejected: payload SHA-256 mismatch", correlationId);
            return new TelemetryIngestResponse("REJECTED_INTEGRITY", correlationId);
        }

        // 6. Parse RBI/NPCI event
        RbiThreatEvent event;
        try {
            event = objectMapper.readValue(plaintext, RbiThreatEvent.class);
        } catch (Exception e) {
            log.error("[{}] Failed to parse decrypted telemetry payload", correlationId, e);
            return new TelemetryIngestResponse("REJECTED_PARSE", correlationId);
        }

        // 7. Structured audit log (no PII)
        log.info("[{}] THREAT_EVENT event_id={} severity={} os={} mask={} categories={} app={}",
                correlationId,
                event.eventId(),
                event.severityLevel(),
                event.osType(),
                event.nativeThreatMask(),
                event.threatVector() != null ? event.threatVector().categories() : "[]",
                event.deviceContext() != null ? event.deviceContext().appId() : "unknown"
        );

        // 8. Fan-out to SSE subscribers (SOC dashboard)
        sseBroker.publish(TelemetrySseEvent.from(event, correlationId));

        return new TelemetryIngestResponse("ACCEPTED", correlationId);
    }
}
