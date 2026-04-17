package org.mazhai.aran.gateway.sigil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * SigilParser — verifies the ES256 signature on an X-Aran-Sigil JWT and
 * extracts {@link SigilClaims}.
 *
 * The EC public key corresponds to the Android KeyStore private key that
 * AranSigilEngine uses to sign each Sigil on-device.
 *
 * Key pinning:
 *   - Public key is embedded in the gateway config (aran.sigil.ec-public-key-b64).
 *   - Loaded from ARAN_SIGIL_EC_PUBLIC_KEY_B64 env var in production.
 *   - Rotation: deploy new key + keep old key for a grace period (72h),
 *     then remove old key in a follow-up deploy.
 */
@Component
public class SigilParser {

    private static final long MAX_CLOCK_SKEW_SEC = 30L;

    private final PublicKey ecPublicKey;

    public SigilParser(
            @Value("${aran.sigil.ec-public-key-b64:}") String ecPublicKeyB64
    ) {
        if (ecPublicKeyB64 == null || ecPublicKeyB64.isBlank()) {
            throw new IllegalStateException(
                "aran.sigil.ec-public-key-b64 is not configured. " +
                "Set ARAN_SIGIL_EC_PUBLIC_KEY_B64 environment variable."
            );
        }
        try {
            byte[] der = Base64.getDecoder().decode(ecPublicKeyB64.replaceAll("\\s", ""));
            this.ecPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load Sigil EC public key", e);
        }
    }

    /**
     * Parse and verify a raw JWT string from the X-Aran-Sigil header.
     *
     * @return verified {@link SigilClaims}
     * @throws SigilVerificationException on any failure (invalid sig, expired, malformed)
     */
    public SigilClaims parse(String rawJwt) {
        if (rawJwt == null || rawJwt.isBlank()) {
            throw new SigilVerificationException("Missing Sigil header");
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(ecPublicKey)
                    .clockSkewSeconds(MAX_CLOCK_SKEW_SEC)
                    .build()
                    .parseSignedClaims(rawJwt)
                    .getPayload();

            int mask = claims.get("mask", Integer.class);

            return new SigilClaims(
                    claims.getSubject(),
                    claims.get("app", String.class),
                    claims.get("src", String.class),
                    mask,
                    claims.getIssuedAt().toInstant().getEpochSecond(),
                    claims.getExpiration().toInstant().getEpochSecond()
            );
        } catch (JwtException e) {
            throw new SigilVerificationException("Sigil JWT invalid: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new SigilVerificationException("Sigil parse error: " + e.getMessage(), e);
        }
    }
}
