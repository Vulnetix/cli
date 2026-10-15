package com.acme.security;

import org.springframework.cache.annotation.Cacheable;

public class PermissionService {
~>    @Cacheable("permissions")
    public boolean hasPermission(long userId, String permission) {
        return repo.existsByUserIdAndPermission(userId, permission);
    }

~>    @Cacheable(value = "roles", key = "#userId")
    public Set<String> loadUserRoles(long userId) {
        return repo.findRoles(userId);
    }
}
