package org.mazhai.central.waf;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * AranSentinel WAF Configuration
 * 
 * Configurable security policies for device posture validation
 */
@Component
@ConfigurationProperties(prefix = "aran.sentinel.waf")
public class WafConfig {

    private boolean blockRooted = true;
    private boolean blockHooked = true;
    private boolean blockEmulator = true;
    private boolean blockTampered = true;
    private boolean blockFrida = true;
    private boolean blockDebugger = true;

    public boolean isBlockRooted() {
        return blockRooted;
    }

    public void setBlockRooted(boolean blockRooted) {
        this.blockRooted = blockRooted;
    }

    public boolean isBlockHooked() {
        return blockHooked;
    }

    public void setBlockHooked(boolean blockHooked) {
        this.blockHooked = blockHooked;
    }

    public boolean isBlockEmulator() {
        return blockEmulator;
    }

    public void setBlockEmulator(boolean blockEmulator) {
        this.blockEmulator = blockEmulator;
    }

    public boolean isBlockTampered() {
        return blockTampered;
    }

    public void setBlockTampered(boolean blockTampered) {
        this.blockTampered = blockTampered;
    }

    public boolean isBlockFrida() {
        return blockFrida;
    }

    public void setBlockFrida(boolean blockFrida) {
        this.blockFrida = blockFrida;
    }

    public boolean isBlockDebugger() {
        return blockDebugger;
    }

    public void setBlockDebugger(boolean blockDebugger) {
        this.blockDebugger = blockDebugger;
    }
}
