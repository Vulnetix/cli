package com.acme.auth;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class PermissionService {
    private final GrantRepository grants;

    public PermissionService(GrantRepository grants) {
        this.grants = grants;
    }

~>    @Cacheable("permissions")
    public boolean hasPermission(long userId, String permission) {
        return grants.existsByUserIdAndPermission(userId, permission);
    }

~>    @Cacheable(value = "roles", key = "#userId")
    public boolean isAuthorized(long userId, String resource) {
        return grants.countByUserIdAndResource(userId, resource) > 0;
    }
}
