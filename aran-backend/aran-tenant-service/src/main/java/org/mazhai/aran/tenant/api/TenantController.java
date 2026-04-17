package org.mazhai.aran.tenant.api;

import jakarta.validation.Valid;
import org.mazhai.aran.tenant.model.Tenant;
import org.mazhai.aran.tenant.service.TenantManagementService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class TenantController {

    private final TenantManagementService tenantManagementService;

    public TenantController(TenantManagementService tenantManagementService) {
        this.tenantManagementService = tenantManagementService;
    }

    @PostMapping("/admin/tenants")
    public ResponseEntity<TenantConfigResponse> createTenant(@Valid @RequestBody CreateTenantRequest request) {
        Tenant tenant = tenantManagementService.createTenant(request.tenantKey(), request.displayName(), request.configJson());
        return ResponseEntity.ok(toResponse(tenant));
    }

    @PostMapping("/admin/tenants/{tenantKey}/suspend")
    public ResponseEntity<TenantConfigResponse> suspendTenant(@PathVariable String tenantKey) {
        Tenant tenant = tenantManagementService.suspendTenant(tenantKey);
        return ResponseEntity.ok(toResponse(tenant));
    }

    @GetMapping("/tenant/config")
    public ResponseEntity<TenantConfigResponse> getTenantConfig(@RequestHeader("X-Tenant-Key") String tenantKey) {
        Tenant tenant = tenantManagementService.getTenantConfig(tenantKey);
        return ResponseEntity.ok(toResponse(tenant));
    }

    private TenantConfigResponse toResponse(Tenant tenant) {
        return new TenantConfigResponse(
                tenant.getTenantKey(),
                tenant.getDisplayName(),
                tenant.getStatus(),
                tenant.getConfigJson()
        );
    }
}
