package org.mazhai.aran.iam.jwks;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * JwksController — serves the JSON Web Key Set consumed by Envoy's jwt_authn filter.
 *
 * Endpoint: GET /api/v1/auth/jwks
 *
 * Envoy configuration:
 *   remote_jwks:
 *     http_uri:
 *       uri: http://aran-iam-service:8081/api/v1/auth/jwks
 *     cache_duration: 300s
 *
 * The response is a standard RFC 7517 JWKS document. Each key entry
 * corresponds to one registered device's EC public key (P-256 / ES256).
 *
 * Cache-Control: public, max-age=290 — slightly under Envoy's 300s to
 * ensure the cache is refreshed before it expires.
 *
 * Key rotation is zero-downtime:
 *   1. New device registers → key added to DeviceKeyStore → appears in JWKS
 *   2. Envoy picks it up within 300s
 *   3. Revoked keys are removed → absent from next JWKS response
 *   4. Envoy drops stale keys automatically on next poll
 */
@RestController
@RequestMapping("/api/v1/auth")
public class JwksController {

    private final DeviceKeyStore deviceKeyStore;

    public JwksController(DeviceKeyStore deviceKeyStore) {
        this.deviceKeyStore = deviceKeyStore;
    }

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> jwks() {
        List<Map<String, Object>> keyList = deviceKeyStore.activeKeys().stream()
                .filter(dk -> dk.publicKey() instanceof ECPublicKey)
                .map(dk -> {
                    ECPublicKey ecKey = (ECPublicKey) dk.publicKey();
                    Map<String, Object> jwk = new LinkedHashMap<>();
                    jwk.put("kty", "EC");
                    jwk.put("use", "sig");
                    jwk.put("alg", "ES256");
                    jwk.put("kid", dk.keyId());
                    jwk.put("crv", "P-256");
                    // X and Y coordinates — base64url-encoded, 32 bytes each for P-256
                    jwk.put("x", encodeCoord(ecKey.getW().getAffineX()));
                    jwk.put("y", encodeCoord(ecKey.getW().getAffineY()));
                    return jwk;
                })
                .toList();

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(290, TimeUnit.SECONDS).cachePublic())
                .body(Map.of("keys", keyList));
    }

    private String encodeCoord(BigInteger coord) {
        byte[] bytes = coord.toByteArray();
        // P-256 coordinates are exactly 32 bytes; BigInteger may prepend a zero sign byte
        if (bytes.length == 33 && bytes[0] == 0) {
            bytes = java.util.Arrays.copyOfRange(bytes, 1, 33);
        } else if (bytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
            bytes = padded;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
