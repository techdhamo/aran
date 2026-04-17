package org.mazhai.aran.gateway.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mazhai.aran.gateway.metrics.WafPolicyMetrics;
import org.mazhai.aran.gateway.sigil.RaspThreatBit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Base64;
import java.util.Map;

/**
 * RaspPolicyRoutingFilter — Global SCG filter that enforces device-health-aware
 * routing based on the X-Aran-Rasp-Mask header injected by Envoy.
 *
 * Request flow:
 *   Envoy jwt_authn → validates ES256, injects X-Aran-Claims + X-Aran-Rasp-Mask
 *   → SCG RaspPolicyRoutingFilter reads the mask and applies policy:
 *
 *   mask == 0  (clean):
 *     → route proceeds normally to upstream banking service
 *
 *   mask has SCREEN / OVERLAY / KEYLOGGER bits (financial UI compromise):
 *     → redirect to /step-up/biometric  (step-up authentication flow)
 *     → audit log with AUDIT_CODE: UI_COMPROMISE
 *
 *   mask has ROOT / FRIDA / DEBUGGER / ZYGISK / ANON_ELF bits (active attack):
 *     → hard 403 with body {"error":"DEVICE_COMPROMISED","audit_code":"RASP_BLOCK"}
 *     → audit log with AUDIT_CODE: CRITICAL_THREAT
 *
 *   mask has TAMPERED / UNTRUSTED_INSTALLER (APK integrity):
 *     → hard 403 with audit code APK_INTEGRITY
 *
 *   mask has PROXY / VPN / UNSECURED_WIFI (network):
 *     → route to read-only sandbox (prefix /sandbox/)
 *     → audit log with AUDIT_CODE: NETWORK_RISK
 *
 * All policy decisions are logged with the device fingerprint (sub) and
 * app ID — no PII.
 */
@Component
public class RaspPolicyRoutingFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RaspPolicyRoutingFilter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final WafPolicyMetrics metrics;

    // ── Internal routing targets (resolved by SCG route config) ──────────────
    private static final String STEP_UP_PREFIX = "/step-up/biometric";
    private static final String SANDBOX_PREFIX = "/sandbox";

    // ── Headers set by Envoy's Lua filter ────────────────────────────────────
    static final String HDR_RASP_MASK  = "X-Aran-Rasp-Mask";
    static final String HDR_DEVICE_ID  = "X-Aran-Device-Id";
    static final String HDR_APP_ID     = "X-Aran-App-Id";
    static final String HDR_POLICY     = "X-Aran-Policy";

    // Paths that bypass RASP policy (already exempted at Envoy level for jwt_authn,
    // but we skip policy evaluation here too for consistency)
    private static final java.util.Set<String> BYPASS_PREFIXES = java.util.Set.of(
        "/api/v1/telemetry/",
        "/api/v1/auth/",
        "/actuator/"
    );

    public RaspPolicyRoutingFilter(WafPolicyMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (BYPASS_PREFIXES.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        String maskHeader = exchange.getRequest().getHeaders().getFirst(HDR_RASP_MASK);
        String deviceId   = exchange.getRequest().getHeaders().getFirst(HDR_DEVICE_ID);
        String appId      = exchange.getRequest().getHeaders().getFirst(HDR_APP_ID);

        // No mask header means Envoy did not inject claims — this should not reach
        // SCG on a production path (Envoy would have blocked it), but guard anyway.
        if (maskHeader == null) {
            log.warn("No X-Aran-Rasp-Mask on request path={} — missing Envoy layer?", path);
            return rejectWithPolicy(exchange, HttpStatus.UNAUTHORIZED, "MISSING_SIGIL", deviceId, appId);
        }

        int mask;
        try {
            mask = Integer.parseInt(maskHeader);
        } catch (NumberFormatException e) {
            log.warn("Malformed X-Aran-Rasp-Mask='{}' path={}", maskHeader, path);
            return rejectWithPolicy(exchange, HttpStatus.BAD_REQUEST, "MALFORMED_MASK", deviceId, appId);
        }

        // ── Clean path ────────────────────────────────────────────────────────
        if (mask == 0) {
            metrics.incrementClean();
            return chain.filter(
                exchange.mutate().request(r -> r.header(HDR_POLICY, "CLEAN")).build()
            );
        }

        // ── Critical: active attack tooling (hard block) ──────────────────────
        if (hasCriticalThreat(mask)) {
            metrics.incrementCriticalThreat();
            log.warn("RASP_BLOCK device={} app={} mask=0x{} path={}",
                deviceId, appId, Integer.toHexString(mask).toUpperCase(), path);
            return rejectWithPolicy(exchange, HttpStatus.FORBIDDEN, "CRITICAL_THREAT", deviceId, appId);
        }

        // ── APK integrity violation (hard block) ─────────────────────────────
        if (hasTamperThreat(mask)) {
            metrics.incrementApkIntegrity();
            log.warn("APK_INTEGRITY device={} app={} mask=0x{} path={}",
                deviceId, appId, Integer.toHexString(mask).toUpperCase(), path);
            return rejectWithPolicy(exchange, HttpStatus.FORBIDDEN, "APK_INTEGRITY", deviceId, appId);
        }

        // ── Financial UI compromise — step-up auth ────────────────────────────
        if (hasUiThreat(mask)) {
            metrics.incrementStepUpRedirect();
            log.warn("UI_COMPROMISE → step-up device={} app={} mask=0x{} path={}",
                deviceId, appId, Integer.toHexString(mask).toUpperCase(), path);
            return redirectToStepUp(exchange, mask, deviceId, appId, path);
        }

        // ── Network risk — sandbox routing ────────────────────────────────────
        if (hasNetworkThreat(mask)) {
            metrics.incrementSandboxRoute();
            log.warn("NETWORK_RISK → sandbox device={} app={} mask=0x{} path={}",
                deviceId, appId, Integer.toHexString(mask).toUpperCase(), path);
            return routeToSandbox(exchange, chain, mask, deviceId, appId, path);
        }

        // ── Low-severity residual flags — allow with policy annotation ────────
        log.info("LOW_RISK device={} mask=0x{} path={} — allowing with annotation",
            deviceId, Integer.toHexString(mask).toUpperCase(), path);
        return chain.filter(
            exchange.mutate().request(r -> r
                .header(HDR_POLICY, "LOW_RISK")
                .header(HDR_RASP_MASK, maskHeader)
            ).build()
        );
    }

    // ── Policy predicates ─────────────────────────────────────────────────────

    private boolean hasCriticalThreat(int mask) {
        return (mask & (RaspThreatBit.ROOT | RaspThreatBit.FRIDA | RaspThreatBit.DEBUGGER |
                        RaspThreatBit.HOOKED | RaspThreatBit.ZYGISK |
                        RaspThreatBit.ANON_ELF | RaspThreatBit.ZYGISK_FD)) != 0;
    }

    private boolean hasTamperThreat(int mask) {
        return (mask & (RaspThreatBit.TAMPERED | RaspThreatBit.UNTRUSTED_INSTALLER |
                        RaspThreatBit.RUNTIME_INTEGRITY | RaspThreatBit.ENV_TAMPERING)) != 0;
    }

    private boolean hasUiThreat(int mask) {
        // Screen recording, overlay, keylogger, untrusted keyboard — financial UI risk
        // These bits live in the Kotlin-only layer; the SDK encodes them in the Sigil mask
        // using the same bitmask scheme (bits 16+ reserved for Kotlin signals)
        final int UI_MASK = 0x010000 | 0x020000 | 0x040000 | 0x080000;
        return (mask & UI_MASK) != 0;
    }

    private boolean hasNetworkThreat(int mask) {
        return (mask & RaspThreatBit.PROXY) != 0;
    }

    // ── Response helpers ──────────────────────────────────────────────────────

    private Mono<Void> rejectWithPolicy(ServerWebExchange exchange, HttpStatus status,
                                         String auditCode, String deviceId, String appId) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        response.getHeaders().add("X-Aran-Audit-Code", auditCode);
        String body = String.format(
            "{\"error\":\"%s\",\"audit_code\":\"%s\"}", auditCode, auditCode);
        var buf = response.bufferFactory().wrap(body.getBytes());
        return response.writeWith(Mono.just(buf));
    }

    private Mono<Void> redirectToStepUp(ServerWebExchange exchange, int mask,
                                         String deviceId, String appId, String originalPath) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FOUND);
        String location = STEP_UP_PREFIX + "?return_to=" +
            java.net.URLEncoder.encode(originalPath, java.nio.charset.StandardCharsets.UTF_8) +
            "&mask=0x" + Integer.toHexString(mask).toUpperCase() +
            "&audit_code=UI_COMPROMISE";
        response.getHeaders().add(HttpHeaders.LOCATION, location);
        response.getHeaders().add("X-Aran-Audit-Code", "UI_COMPROMISE");
        return response.setComplete();
    }

    private Mono<Void> routeToSandbox(ServerWebExchange exchange, GatewayFilterChain chain,
                                       int mask, String deviceId, String appId, String path) {
        // Rewrite path to /sandbox<original_path> — handled by sandbox-routes in application.yml
        String sandboxPath = SANDBOX_PREFIX + path;
        var sandboxRequest = exchange.getRequest().mutate()
            .path(sandboxPath)
            .header(HDR_POLICY, "SANDBOX")
            .header(HDR_RASP_MASK, String.valueOf(mask))
            .build();
        return chain.filter(exchange.mutate().request(sandboxRequest).build());
    }
}
