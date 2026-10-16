package com.acme.idp;

public final class TenantPolicyFactory {
    private TenantPolicyFactory() {}

    public static TenantPolicy defaults(String tenantId) {
        return TenantPolicy.builder()
                .tenantId(tenantId)
                .passwordMinLength(12)
~>                .requireMfa(false)
                .build();
    }
}
