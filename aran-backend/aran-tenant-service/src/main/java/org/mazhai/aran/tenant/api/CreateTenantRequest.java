package org.mazhai.aran.tenant.api;

import jakarta.validation.constraints.NotBlank;

public record CreateTenantRequest(
        @NotBlank String tenantKey,
        @NotBlank String displayName,
        String configJson
) {
}
