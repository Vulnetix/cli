package app;

import org.springframework.cache.annotation.Cacheable;

public class PermissionService {
~>    @Cacheable("permissions")
    public Set<String> getPermissionsForUser(Long userId) {
        return repo.findPermissions(userId);
    }

~>    @Cacheable(value = "admins", key = "#userId")
    public boolean isAdmin(Long userId) {
        return repo.isAdmin(userId);
    }
}
