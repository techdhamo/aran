package org.mazhai.aran.gateway.sigil;

/**
 * Parsed, verified claims from an X-Aran-Sigil JWT.
 *
 * The Sigil is an ES256 JWT produced by AranSigilEngine on the device:
 *   {
 *     "sub":  "<deviceFingerprint>",
 *     "iss":  "aran-sdk",
 *     "iat":  <unix seconds>,
 *     "exp":  <unix seconds>,
 *     "mask": <integer — native threat bitmask>,
 *     "app":  "<packageName>",
 *     "src":  "<trafficSource>"  // WEBVIEW | NATIVE
 *   }
 *
 * A "clean" mask has no threat bits set (mask == 0).
 * A "dirty" mask has one or more bits set (mask != 0).
 * Specific bit meanings are defined in RaspThreatBit.
 */
public record SigilClaims(
        String deviceFingerprint,
        String appId,
        String trafficSource,
        int    raspMask,
        long   issuedAtEpochSec,
        long   expiresAtEpochSec
) {
    public boolean isClean() {
        return raspMask == 0;
    }

    public boolean hasPrivilegeEscalation() {
        return (raspMask & RaspThreatBit.PRIVILEGE_ESCALATION_MASK) != 0;
    }

    public boolean hasDynamicInstrumentation() {
        return (raspMask & RaspThreatBit.DYNAMIC_INSTRUMENTATION_MASK) != 0;
    }

    public boolean hasTampering() {
        return (raspMask & RaspThreatBit.TAMPER_MASK) != 0;
    }

    public boolean hasNetworkInterception() {
        return (raspMask & RaspThreatBit.NETWORK_MASK) != 0;
    }

    /** True when the mask carries any high-severity threat. */
    public boolean isCritical() {
        return hasPrivilegeEscalation() || hasDynamicInstrumentation() || hasTampering();
    }
}
