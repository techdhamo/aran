package org.mazhai.central.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Cryptographic Service for End-to-End Encryption (E2EE)
 * 
 * Security Architecture:
 * - AES-256-GCM for payload encryption (authenticated encryption)
 * - HMAC-SHA256 for message authentication and anti-tampering
 * - Nonce + Timestamp for replay attack prevention
 * - Base64 encoding for transport
 * 
 * Triple-Layer MITM Defense:
 * 1. TLS/SSL with certificate pinning (transport layer)
 * 2. AES-256-GCM application-layer encryption (this service)
 * 3. HMAC-SHA256 signature verification (anti-tampering)
 */
@Service
public class CryptoService {

    private static final Logger log = LoggerFactory.getLogger(CryptoService.class);

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128 bits authentication tag
    private static final int AES_KEY_SIZE = 256; // 256 bits

    // PRODUCTION: Load from secure vault (AWS Secrets Manager, HashiCorp Vault)
    // DEV: Hardcoded for demonstration
    private static final String MASTER_AES_KEY_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 bytes
    private static final String HMAC_SECRET_BASE64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 32 bytes

    private final SecretKey masterAesKey;
    private final SecretKey hmacSecret;
    private final SecureRandom secureRandom;

    public CryptoService() {
        try {
            // Initialize master keys
            byte[] aesKeyBytes = Base64.getDecoder().decode(MASTER_AES_KEY_BASE64);
            byte[] hmacKeyBytes = Base64.getDecoder().decode(HMAC_SECRET_BASE64);
            
            this.masterAesKey = new SecretKeySpec(aesKeyBytes, "AES");
            this.hmacSecret = new SecretKeySpec(hmacKeyBytes, HMAC_ALGORITHM);
            this.secureRandom = new SecureRandom();
            
            log.info("CryptoService initialized: AES-256-GCM + HMAC-SHA256");
        } catch (Exception e) {
            log.error("CRITICAL: Failed to initialize CryptoService", e);
            throw new RuntimeException("Crypto initialization failed", e);
        }
    }

    /**
     * Encrypt and sign a JSON payload for RASP SDK
     * 
     * @param plaintext JSON string to encrypt
     * @param nonce Client-provided nonce (UUID) for replay attack prevention
     * @param timestamp Client-provided timestamp (milliseconds)
     * @return Base64-encoded encrypted payload with HMAC signature
     */
    public EncryptedPayload encryptAndSign(String plaintext, String nonce, long timestamp) {
        try {
            // Step 1: Validate replay attack prevention
            validateTimestamp(timestamp);

            // Step 2: Generate random IV for AES-GCM
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Step 3: Encrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterAesKey, gcmSpec);
            
            // Add nonce and timestamp as Additional Authenticated Data (AAD)
            String aad = nonce + ":" + timestamp;
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Step 4: Combine IV + Ciphertext
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            byteBuffer.put(iv);
            byteBuffer.put(ciphertext);
            byte[] ivAndCiphertext = byteBuffer.array();

            // Step 5: Generate HMAC signature over (IV + Ciphertext + AAD)
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(hmacSecret);
            hmac.update(ivAndCiphertext);
            hmac.update(aad.getBytes(StandardCharsets.UTF_8));
            byte[] signature = hmac.doFinal();

            // Step 6: Base64 encode for transport
            String encryptedData = Base64.getEncoder().encodeToString(ivAndCiphertext);
            String signatureB64 = Base64.getEncoder().encodeToString(signature);

            log.debug("Encrypted payload: {} bytes, HMAC: {} bytes", ivAndCiphertext.length, signature.length);
            return new EncryptedPayload(encryptedData, signatureB64, nonce, timestamp);

        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new CryptoException("Failed to encrypt payload", e);
        }
    }

    /**
     * Verify HMAC signature and decrypt payload from RASP SDK
     * 
     * @param encryptedData Base64-encoded (IV + Ciphertext)
     * @param signature Base64-encoded HMAC-SHA256 signature
     * @param nonce Client-provided nonce
     * @param timestamp Client-provided timestamp
     * @return Decrypted plaintext JSON
     */
    public String verifyAndDecrypt(String encryptedData, String signature, String nonce, long timestamp) {
        try {
            // Step 1: Validate replay attack prevention
            validateTimestamp(timestamp);

            // Step 2: Decode Base64
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedData);
            byte[] expectedSignature = Base64.getDecoder().decode(signature);

            // Step 3: Verify HMAC signature (CRITICAL: Anti-Tampering)
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(hmacSecret);
            String aad = nonce + ":" + timestamp;
            hmac.update(ivAndCiphertext);
            hmac.update(aad.getBytes(StandardCharsets.UTF_8));
            byte[] computedSignature = hmac.doFinal();

            if (!MessageDigest.isEqual(expectedSignature, computedSignature)) {
                log.error("SECURITY ALERT: HMAC verification failed - possible tampering detected!");
                throw new CryptoException("HMAC verification failed - payload tampered");
            }

            // Step 4: Extract IV and Ciphertext
            ByteBuffer byteBuffer = ByteBuffer.wrap(ivAndCiphertext);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] ciphertext = new byte[byteBuffer.remaining()];
            byteBuffer.get(ciphertext);

            // Step 5: Decrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterAesKey, gcmSpec);
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            
            byte[] plaintext = cipher.doFinal(ciphertext);

            log.debug("Decrypted payload: {} bytes", plaintext.length);
            return new String(plaintext, StandardCharsets.UTF_8);

        } catch (CryptoException e) {
            throw e; // Re-throw crypto exceptions
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new CryptoException("Failed to decrypt payload", e);
        }
    }

    /**
     * Validate timestamp to prevent replay attacks
     * Allows 5-minute clock skew tolerance
     */
    private void validateTimestamp(long timestamp) {
        long currentTime = System.currentTimeMillis();
        long timeDiff = Math.abs(currentTime - timestamp);
        long maxSkew = 5 * 60 * 1000; // 5 minutes

        if (timeDiff > maxSkew) {
            log.warn("SECURITY ALERT: Timestamp out of range - possible replay attack! Diff: {}ms", timeDiff);
            throw new CryptoException("Timestamp validation failed - possible replay attack");
        }
    }

    /**
     * Generate a new AES-256 key (for key rotation)
     */
    public SecretKey generateAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE, secureRandom);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new CryptoException("Failed to generate AES key", e);
        }
    }

    /**
     * Encrypted payload container
     */
    public record EncryptedPayload(
        String encryptedData,  // Base64(IV + Ciphertext)
        String signature,      // Base64(HMAC-SHA256)
        String nonce,          // UUID for replay prevention
        long timestamp         // Milliseconds since epoch
    ) {}

    /**
     * Custom exception for crypto operations
     */
    public static class CryptoException extends RuntimeException {
        public CryptoException(String message) {
            super(message);
        }
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
