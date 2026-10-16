package com.acme.tenancy;

public class TenantGuard {

    private final Long tenantId;

    public TenantGuard(Long tenantId) {
        this.tenantId = tenantId;
    }

    public void check(Document doc) {
        Long ownerTenant = doc.getTenantId();
~>        if (ownerTenant != tenantId) {
            throw new AccessDeniedException("document belongs to another tenant");
        }
    }
}
