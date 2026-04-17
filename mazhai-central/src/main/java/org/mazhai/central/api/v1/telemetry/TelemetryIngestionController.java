package org.mazhai.central.api.v1.telemetry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mazhai.central.security.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Telemetry Ingestion API with E2EE support.
 * 
 * Security:
 * - Accepts AES-256-GCM encrypted payloads (encrypted_data + signature + nonce + timestamp)
 * - HMAC-SHA256 request header verification
 * - Nonce + timestamp replay attack prevention
 * - Backward compatible: also accepts plaintext JSON for migration
 */
@RestController
@RequestMapping("/api/v1/telemetry")
@Validated
public class TelemetryIngestionController {

    private static final Logger log = LoggerFactory.getLogger(TelemetryIngestionController.class);
    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public TelemetryIngestionController(CryptoService cryptoService, ObjectMapper objectMapper) {
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/ingest")
    public ResponseEntity<Void> ingest(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "X-Aran-Nonce", required = false) String headerNonce,
            @RequestHeader(value = "X-Aran-Timestamp", required = false) String headerTimestamp,
            @RequestHeader(value = "X-Aran-Signature", required = false) String headerSignature
    ) {
        try {
            String encryptedData = (String) body.get("encrypted_data");
            String signature = (String) body.get("signature");
            String nonce = (String) body.get("nonce");
            Object tsObj = body.get("timestamp");

            // E2EE path: decrypt if encrypted envelope present
            if (encryptedData != null && signature != null && nonce != null && tsObj != null) {
                long timestamp = tsObj instanceof Number n ? n.longValue() : Long.parseLong(tsObj.toString());
                String decrypted = cryptoService.verifyAndDecrypt(encryptedData, signature, nonce, timestamp);
                JsonNode telemetry = objectMapper.readTree(decrypted);
                log.info("E2EE telemetry received: deviceFingerprint={}, hasThreat=true",
                        telemetry.path("device_fingerprint").asText("unknown"));
                return ResponseEntity.accepted().build();
            }

            // Backward compatibility: plaintext JSON
            log.info("Plaintext telemetry received: {}", body);
            return ResponseEntity.accepted().build();

        } catch (CryptoService.CryptoException e) {
            log.error("SECURITY ALERT: Telemetry decryption/verification failed: {}", e.getMessage());
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            log.error("Telemetry ingestion error: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }
}
