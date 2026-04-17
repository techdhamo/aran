package org.mazhai.central;

import org.mazhai.central.waf.EnableAranSentinel;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Mazhai Central - Aran RASP Backend
 * 
 * This is the RASP infrastructure server that provides:
 * - Config sync for RASP SDKs
 * - Telemetry ingestion
 * - Multi-tenant threat intelligence
 * - Admin APIs for tenant management
 * 
 * AranSentinel WAF is enabled ONLY for demo business endpoints (/api/v1/business/*).
 * RASP infrastructure endpoints (/api/v1/config/*, /api/v1/telemetry/*, /api/v1/admin/*)
 * are excluded from WAF validation to avoid circular dependencies.
 */
@SpringBootApplication
@EnableAranSentinel  // WAF enabled - but excludes RASP infrastructure endpoints
public class MazhaiCentralApplication {

    public static void main(String[] args) {
        SpringApplication.run(MazhaiCentralApplication.class, args);
    }
}
