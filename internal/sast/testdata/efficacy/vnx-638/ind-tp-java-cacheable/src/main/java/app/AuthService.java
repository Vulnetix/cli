package app;

import org.springframework.cache.annotation.Cacheable;

public class AuthService {
~>    @Cacheable("permissions")
    public boolean hasPermission(long userId, String permission) {
        return repo.exists(userId, permission);
    }
}
