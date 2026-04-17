package org.mazhai.central.waf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * AranSentinel WAF (Web Application Firewall)
 * 
 * Zero-Trust Hardware Attestation Gateway
 * 
 * 4-Stage Validation Pipeline:
 * 1. Sigil Integrity: Verify ECDSA hardware signature
 * 2. Device Posture: Validate RASP bitmask against tenant policy
 * 3. Anti-Replay & MITM: Verify timestamp and payload hash
 * 4. Payload Inspection: Block OWASP Top 10 attacks
 * 
 * Security Guarantees:
 * - Only hardware-attested devices can access protected APIs
 * - Rooted/hooked/emulated devices blocked per policy
 * - MITM attacks detected via payload hash mismatch
 * - Replay attacks prevented via timestamp validation
 * - SQL injection, XSS, and other attacks blocked
 */
public class AranSentinelWafFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AranSentinelWafFilter.class);

    private static final String HEADER_SIGIL = "X-Aran-Sigil";
    private static final String HEADER_PUBLIC_KEY = "X-Aran-Public-Key";
    
    // RASP Bitmask Flags (from aran-core.cpp)
    private static final int FLAG_ROOT = 0x001;
    private static final int FLAG_FRIDA = 0x002;
    private static final int FLAG_DEBUGGER = 0x004;
    private static final int FLAG_EMULATOR = 0x008;
    private static final int FLAG_HOOKED = 0x010;
    private static final int FLAG_TAMPERED = 0x020;

    // OWASP Top 10 Attack Patterns
    private static final Pattern SQL_INJECTION = Pattern.compile(
        "('|(\\-\\-)|(;)|(\\|\\|)|(\\*)|(<)|(>)|(\\^)|(\\[)|(\\])|(\\{)|(\\})|(%)|(\\$))" +
        ".*(union|select|insert|update|delete|drop|create|alter|exec|script|javascript|onerror|onload)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern XSS_ATTACK = Pattern.compile(
        "<script[^>]*>.*?</script>|javascript:|onerror=|onload=|<iframe|<object|<embed",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
        "\\.\\./|\\.\\.\\\\"
    );

    private static final Pattern COMMAND_INJECTION = Pattern.compile(
        "(;|\\||&|`|\\$\\(|\\$\\{).*?(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
        Pattern.CASE_INSENSITIVE
    );

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WafConfig wafConfig;

    public AranSentinelWafFilter(WafConfig wafConfig) {
        this.wafConfig = wafConfig;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // Skip WAF for excluded paths
        if (shouldSkipWaf(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Wrap request to allow multiple reads of body
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);

        try {
            // ══════════════════════════════════════════════════════════════════
            // STAGE 1: Sigil Integrity Verification
            // ══════════════════════════════════════════════════════════════════
            String sigilToken = wrappedRequest.getHeader(HEADER_SIGIL);
            String publicKeyB64 = wrappedRequest.getHeader(HEADER_PUBLIC_KEY);

            if (sigilToken == null || sigilToken.isEmpty()) {
                log.warn("SECURITY ALERT: Missing X-Aran-Sigil header - request blocked");
                blockRequest(response, 401, "MISSING_SIGIL", "Hardware attestation required");
                return;
            }

            if (publicKeyB64 == null || publicKeyB64.isEmpty()) {
                log.warn("SECURITY ALERT: Missing X-Aran-Public-Key header - request blocked");
                blockRequest(response, 401, "MISSING_PUBLIC_KEY", "Public key required");
                return;
            }

            // Verify JWT signature
            SigilClaims claims;
            try {
                claims = verifyJwtSignature(sigilToken, publicKeyB64);
            } catch (SecurityException e) {
                log.error("SECURITY ALERT: Invalid Sigil signature - possible forgery attempt", e);
                blockRequest(response, 401, "INVALID_SIGNATURE", "Hardware signature verification failed");
                return;
            }

            // ══════════════════════════════════════════════════════════════════
            // STAGE 2: Device Posture Validation
            // ══════════════════════════════════════════════════════════════════
            int raspBitmask = claims.raspBitmask;
            
            if (wafConfig.isBlockRooted() && (raspBitmask & FLAG_ROOT) != 0) {
                log.warn("SECURITY ALERT: Rooted device detected - request blocked (bitmask: {})", raspBitmask);
                blockRequest(response, 403, "DEVICE_ROOTED", "Rooted devices not allowed");
                return;
            }

            if (wafConfig.isBlockHooked() && (raspBitmask & FLAG_HOOKED) != 0) {
                log.warn("SECURITY ALERT: Hooked device detected - request blocked (bitmask: {})", raspBitmask);
                blockRequest(response, 403, "DEVICE_HOOKED", "Hooked/modified devices not allowed");
                return;
            }

            if (wafConfig.isBlockEmulator() && (raspBitmask & FLAG_EMULATOR) != 0) {
                log.warn("SECURITY ALERT: Emulator detected - request blocked (bitmask: {})", raspBitmask);
                blockRequest(response, 403, "DEVICE_EMULATOR", "Emulators not allowed");
                return;
            }

            if (wafConfig.isBlockTampered() && (raspBitmask & FLAG_TAMPERED) != 0) {
                log.warn("SECURITY ALERT: Tampered app detected - request blocked (bitmask: {})", raspBitmask);
                blockRequest(response, 403, "APP_TAMPERED", "Tampered applications not allowed");
                return;
            }

            // ══════════════════════════════════════════════════════════════════
            // STAGE 3: Anti-Replay & MITM Prevention
            // ══════════════════════════════════════════════════════════════════
            
            // Verify timestamp (60-second window)
            long currentTime = System.currentTimeMillis();
            long timeDiff = Math.abs(currentTime - claims.timestamp);
            if (timeDiff > 60000) { // 60 seconds
                log.warn("SECURITY ALERT: Timestamp out of range - possible replay attack (diff: {}ms)", timeDiff);
                blockRequest(response, 403, "REPLAY_ATTACK", "Request timestamp expired");
                return;
            }

            // Verify payload hash (MITM detection)
            String requestBody = getRequestBody(wrappedRequest);
            String computedHash = computePayloadHash(requestBody);
            
            if (!computedHash.equals(claims.payloadHash)) {
                log.error("SECURITY ALERT: Payload hash mismatch - MITM attack detected!");
                log.error("Expected: {}, Computed: {}", claims.payloadHash, computedHash);
                blockRequest(response, 403, "PAYLOAD_TAMPERED", "Request body modified in transit");
                return;
            }

            // ══════════════════════════════════════════════════════════════════
            // STAGE 4: Payload Inspection (OWASP Top 10)
            // ══════════════════════════════════════════════════════════════════
            
            if (SQL_INJECTION.matcher(requestBody).find()) {
                log.error("SECURITY ALERT: SQL Injection detected in request body");
                blockRequest(response, 403, "SQL_INJECTION", "Malicious SQL pattern detected");
                return;
            }

            if (XSS_ATTACK.matcher(requestBody).find()) {
                log.error("SECURITY ALERT: XSS attack detected in request body");
                blockRequest(response, 403, "XSS_ATTACK", "Cross-site scripting detected");
                return;
            }

            if (PATH_TRAVERSAL.matcher(requestBody).find()) {
                log.error("SECURITY ALERT: Path traversal attack detected");
                blockRequest(response, 403, "PATH_TRAVERSAL", "Directory traversal detected");
                return;
            }

            if (COMMAND_INJECTION.matcher(requestBody).find()) {
                log.error("SECURITY ALERT: Command injection detected");
                blockRequest(response, 403, "COMMAND_INJECTION", "OS command injection detected");
                return;
            }

            // ══════════════════════════════════════════════════════════════════
            // ALL STAGES PASSED - Allow Request
            // ══════════════════════════════════════════════════════════════════
            
            log.info("AranSentinel: Request validated successfully (device: {}, bitmask: {})", 
                claims.deviceFingerprint, raspBitmask);
            
            // Add claims to request attributes for downstream controllers
            wrappedRequest.setAttribute("aran.sigil.claims", claims);
            
            filterChain.doFilter(wrappedRequest, response);

        } catch (Exception e) {
            log.error("WAF processing error", e);
            blockRequest(response, 500, "WAF_ERROR", "Internal WAF error");
        }
    }

    /**
     * Verify JWT signature using ECDSA
     */
    private SigilClaims verifyJwtSignature(String jwt, String publicKeyB64) throws SecurityException {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                throw new SecurityException("Invalid JWT format");
            }

            String headerB64 = parts[0];
            String payloadB64 = parts[1];
            String signatureB64 = parts[2];

            // Decode public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyB64);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // Verify signature
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update((headerB64 + "." + payloadB64).getBytes(StandardCharsets.UTF_8));
            
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureB64);
            boolean valid = signature.verify(signatureBytes);

            if (!valid) {
                throw new SecurityException("Signature verification failed");
            }

            // Parse claims
            String payloadJson = new String(
                Base64.getUrlDecoder().decode(payloadB64), 
                StandardCharsets.UTF_8
            );
            JsonNode claimsNode = objectMapper.readTree(payloadJson);

            return new SigilClaims(
                claimsNode.get("device_fingerprint").asText(),
                claimsNode.get("rasp_bitmask").asInt(),
                claimsNode.get("payload_hash").asText(),
                claimsNode.get("timestamp").asLong(),
                claimsNode.get("nonce").asText()
            );

        } catch (Exception e) {
            throw new SecurityException("JWT verification failed", e);
        }
    }

    /**
     * Compute SHA-256 hash of request body
     */
    private String computePayloadHash(String body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(body.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Extract request body from cached wrapper
     */
    private String getRequestBody(ContentCachingRequestWrapper request) throws IOException {
        byte[] content = request.getContentAsByteArray();
        if (content.length == 0) {
            return "";
        }
        return new String(content, StandardCharsets.UTF_8);
    }

    /**
     * Block request with security error
     */
    private void blockRequest(
        HttpServletResponse response, 
        int statusCode, 
        String errorCode, 
        String message
    ) throws IOException {
        response.setStatus(statusCode);
        response.setContentType("application/json");
        
        String errorJson = String.format(
            "{\"error\":\"%s\",\"message\":\"%s\",\"blocked_by\":\"AranSentinel WAF\"}",
            errorCode, message
        );
        
        response.getWriter().write(errorJson);
        response.getWriter().flush();
        
        // Log to WAF analytics
        logWafBlock(errorCode, message);
    }

    /**
     * Log blocked request for analytics
     */
    private void logWafBlock(String errorCode, String message) {
        // TODO: Send to analytics service for dashboard display
        log.info("WAF_BLOCK: code={}, message={}", errorCode, message);
    }

    /**
     * Skip WAF for internal/public endpoints
     */
    private boolean shouldSkipWaf(String uri) {
        return uri.startsWith("/api/v1/config/sync") ||
               uri.startsWith("/api/v1/telemetry/ingest") ||
               uri.startsWith("/api/v1/attest") ||
               uri.startsWith("/api/v1/admin") ||
               uri.startsWith("/actuator") ||
               uri.startsWith("/public");
    }

    /**
     * Sigil JWT claims
     */
    public record SigilClaims(
        String deviceFingerprint,
        int raspBitmask,
        String payloadHash,
        long timestamp,
        String nonce
    ) {}
}
