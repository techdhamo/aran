package org.mazhai.central.repository;

import org.mazhai.central.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Tenant Repository - Database Access Layer
 */
@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {
    
    Optional<Tenant> findByLicenseKey(String licenseKey);
    
    boolean existsByLicenseKey(String licenseKey);
    
    boolean existsByOrganizationName(String organizationName);
}
