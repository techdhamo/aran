package org.mazhai.aran.telemetry.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * TelemetryCryptoService
 *
 * Decrypts RSA-OAEP + AES-256-GCM telemetry blobs received from the SDK.
 *
 * Private key lifecycle:
 *   - Loaded from environment variable ARAN_RSA_PRIVATE_KEY_B64 (PKCS8 DER, Base64)
 *     which is injected at container startup from the KMS secret store.
 *   - Never committed to source control or logged.
 *   - Rotated annually via Phantom Channel public-key update.
 */
@Service
public class TelemetryCryptoService {

    private static final String RSA_ALGORITHM  = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ALGORITHM  = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_BITS   = 128;

    private PrivateKey privateKey;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public TelemetryCryptoService(
            @Value("${aran.telemetry.rsa-private-key-b64:}") String rsaPrivateKeyB64
    ) {
        if (rsaPrivateKeyB64 == null || rsaPrivateKeyB64.isBlank()) {
            // For development/testing: allow service to start without encryption
            this.privateKey = null;
            return;
        }
        try {
            byte[] der = Base64.getDecoder().decode(rsaPrivateKeyB64.replaceAll("\\s", ""));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            // For development/testing: allow service to start with invalid key
            this.privateKey = null;
        }
    }

    /**
     * Decrypt an encrypted blob produced by the Android/iOS SDK.
     *
     * @param encryptedBlobB64 Base64-encoded JSON bundle {enc_key, iv, ct}
     * @return Decrypted UTF-8 plaintext (RBI/NPCI JSON payload)
     * @throws TelemetryDecryptionException on any failure
     */
    public String decrypt(String encryptedBlobB64) {
        if (privateKey == null) {
            throw new TelemetryDecryptionException("Encryption not configured - RSA private key not loaded", new IllegalStateException("RSA private key not loaded"));
        }
        try {
            byte[] bundleBytes = Base64.getDecoder().decode(encryptedBlobB64);
            JsonNode bundle = objectMapper.readTree(bundleBytes);

            byte[] encKey    = Base64.getDecoder().decode(bundle.get("enc_key").asText());
            byte[] iv        = Base64.getDecoder().decode(bundle.get("iv").asText());
            byte[] ciphertext = Base64.getDecoder().decode(bundle.get("ct").asText());

            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encKey);

            SecretKey sessionKey = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

            byte[] plainBytes = aesCipher.doFinal(ciphertext);
            return new String(plainBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new TelemetryDecryptionException("Failed to decrypt telemetry blob", e);
        }
    }

    /**
     * Verify SHA-256 of decrypted plaintext matches the SDK-provided digest.
     *
     * @param plaintext     decrypted payload string
     * @param expectedB64   Base64-encoded SHA-256 from the envelope header
     * @return true if digests match
     */
    public boolean verifyPayloadIntegrity(String plaintext, String expectedB64) {
        if (expectedB64 == null || expectedB64.isBlank()) return true;
        try {
            byte[] actual = MessageDigest.getInstance("SHA-256")
                    .digest(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] expected = Base64.getDecoder().decode(expectedB64);
            return MessageDigest.isEqual(actual, expected);
        } catch (Exception e) {
            return false;
        }
    }
}
