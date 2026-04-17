package org.mazhai.aran.gateway.api;

import org.mazhai.aran.gateway.metrics.WafPolicyMetrics;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WafMetricsController — Exposes WAF policy decision metrics for SOC dashboard.
 *
 * GET /api/v1/gateway/metrics/waf-policy returns real-time counters for:
 *   - CRITICAL_THREAT (ROOT, FRIDA, ZYGISK, ANON_ELF)
 *   - APK_INTEGRITY (TAMPERED, UNTRUSTED_INSTALLER)
 *   - STEP_UP_REDIRECT (OVERLAY, SCREEN_RECORDING)
 *   - SANDBOX_ROUTE (PROXY)
 *   - CLEAN (mask == 0)
 *
 * These counters are incremented by RaspPolicyRoutingFilter on every request.
 * The endpoint is public (no auth) for SOC dashboard consumption.
 */
@RestController
@RequestMapping("/api/v1/gateway/metrics")
public class WafMetricsController {

    private final WafPolicyMetrics metrics;

    public WafMetricsController(WafPolicyMetrics metrics) {
        this.metrics = metrics;
    }

    @GetMapping("/waf-policy")
    public ResponseEntity<WafPolicyMetrics.WafPolicyStats> getWafPolicyStats() {
        return ResponseEntity.ok(metrics.snapshot());
    }
}
