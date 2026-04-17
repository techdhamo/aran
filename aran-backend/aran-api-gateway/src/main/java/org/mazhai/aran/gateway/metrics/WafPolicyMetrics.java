package org.mazhai.aran.gateway.metrics;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

/**
 * WafPolicyMetrics — Tracks RaspPolicyRoutingFilter decision counts.
 *
 * Thread-safe counters for each policy outcome:
 *   - CRITICAL_THREAT: ROOT, FRIDA, ZYGISK, ANON_ELF → hard 403
 *   - APK_INTEGRITY: TAMPERED, UNTRUSTED_INSTALLER → hard 403
 *   - STEP_UP_REDIRECT: OVERLAY, SCREEN_RECORDING → 302 to biometric
 *   - SANDBOX_ROUTE: PROXY → rewrite to /sandbox/
 *   - CLEAN: mask == 0 → normal routing
 *
 * These counters are exposed via GET /api/v1/gateway/metrics/waf-policy
 * for the SOC dashboard WAF policy breakdown panel.
 */
@Component
public class WafPolicyMetrics {

    private final AtomicLong criticalThreat = new AtomicLong(0);
    private final AtomicLong apkIntegrity = new AtomicLong(0);
    private final AtomicLong stepUpRedirect = new AtomicLong(0);
    private final AtomicLong sandboxRoute = new AtomicLong(0);
    private final AtomicLong clean = new AtomicLong(0);

    public void incrementCriticalThreat() {
        criticalThreat.incrementAndGet();
    }

    public void incrementApkIntegrity() {
        apkIntegrity.incrementAndGet();
    }

    public void incrementStepUpRedirect() {
        stepUpRedirect.incrementAndGet();
    }

    public void incrementSandboxRoute() {
        sandboxRoute.incrementAndGet();
    }

    public void incrementClean() {
        clean.incrementAndGet();
    }

    public WafPolicyStats snapshot() {
        return new WafPolicyStats(
            criticalThreat.get(),
            apkIntegrity.get(),
            stepUpRedirect.get(),
            sandboxRoute.get(),
            clean.get()
        );
    }

    public void reset() {
        criticalThreat.set(0);
        apkIntegrity.set(0);
        stepUpRedirect.set(0);
        sandboxRoute.set(0);
        clean.set(0);
    }

    public record WafPolicyStats(
        long criticalThreat,
        long apkIntegrity,
        long stepUpRedirect,
        long sandboxRoute,
        long clean
    ) {
        public long total() {
            return criticalThreat + apkIntegrity + stepUpRedirect + sandboxRoute + clean;
        }
    }
}
