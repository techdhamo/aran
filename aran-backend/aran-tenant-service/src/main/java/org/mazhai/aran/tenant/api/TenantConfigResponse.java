package org.mazhai.aran.tenant.api;

public record TenantConfigResponse(
        String tenantKey,
        String displayName,
        String status,
        String configJson
) {
}
