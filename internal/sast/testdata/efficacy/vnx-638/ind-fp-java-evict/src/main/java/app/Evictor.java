package app;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;

public class Evictor {
    @CacheEvict(value = "permissions", allEntries = true)
    public void revokePermission(long userId) {}

    @Cacheable("labels")
    public String formatDate(long ts) { return Long.toString(ts); }
}
