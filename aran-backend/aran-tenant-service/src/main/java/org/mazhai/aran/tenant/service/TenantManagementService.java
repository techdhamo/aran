package org.mazhai.aran.tenant.service;

import org.mazhai.aran.tenant.model.Tenant;
import org.mazhai.aran.tenant.repo.TenantRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class TenantManagementService {

    private final TenantRepository tenantRepository;

    public TenantManagementService(TenantRepository tenantRepository) {
        this.tenantRepository = tenantRepository;
    }

    public Tenant createTenant(String tenantKey, String displayName, String configJson) {
        Tenant tenant = new Tenant();
        tenant.setTenantKey(tenantKey);
        tenant.setDisplayName(displayName);
        tenant.setStatus("ACTIVE");
        tenant.setConfigJson(configJson == null || configJson.isBlank() ? "{}" : configJson);
        return tenantRepository.save(tenant);
    }

    public Tenant suspendTenant(String tenantKey) {
        Tenant tenant = tenantRepository.findByTenantKey(tenantKey)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + tenantKey));
        tenant.setStatus("SUSPENDED");
        return tenantRepository.save(tenant);
    }

    public Tenant getTenantConfig(String tenantKey) {
        return tenantRepository.findByTenantKey(tenantKey)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + tenantKey));
    }
}
