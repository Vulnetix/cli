package app;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;

public class RoleCatalog {
    @CacheEvict(value = "permissions", allEntries = true)
    public void hasPermissionChanged() {}

    @Cacheable("roleLabels")
    public String getRoleDescription(String role) {
        return labels.get(role);
    }
}
