package com.acme.auth;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class GrantAdmin {
    @CacheEvict(value = "permissions", allEntries = true)
    public void revokePermission(long userId, String permission) {
        grants.deleteByUserIdAndPermission(userId, permission);
    }

    @Cacheable("labels")
    public String getRoleLabel(String role) {
        return labels.lookup(role);
    }

    @Cacheable("countries")
    public java.util.List<String> listCountries() {
        return countries.findAll();
    }
}
