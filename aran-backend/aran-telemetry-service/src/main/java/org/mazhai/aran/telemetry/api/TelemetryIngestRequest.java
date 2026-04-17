package org.mazhai.aran.telemetry.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Schema v2.0 — asymmetric-encrypted telemetry envelope.
 *
 * The SDK encrypts each event with a hybrid RSA-OAEP + AES-256-GCM scheme:
 *   encrypted_blob = Base64( JSON{ enc_key, iv, ct } )
 * where:
 *   enc_key = RSA-OAEP-encrypted AES-256 session key
 *   iv      = 12-byte AES-GCM nonce
 *   ct      = AES-GCM ciphertext of the RBI payload JSON
 *
 * Only the backend RSA private key (stored in KMS) can decrypt enc_key.
 */
public record TelemetryIngestRequest(
        @NotBlank @JsonProperty("schema_version") String schemaVersion,
        @NotBlank @JsonProperty("enc_algorithm")  String encAlgorithm,
        @NotBlank @JsonProperty("encrypted_blob") String encryptedBlob,
        @NotBlank String nonce,
        @NotNull  Long timestamp,
        @JsonProperty("payload_sha256") String payloadSha256
) {
}
