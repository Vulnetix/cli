package com.acme.tenancy;

import java.util.HashMap;
import java.util.Map;

public class TenantCache {
    private final Map<String, Object> cache = new HashMap<>();

    public Object load(String tenantId, Loader loader) {
~>        synchronized (tenantId.intern()) {
            return cache.computeIfAbsent(tenantId, loader::load);
        }
    }

    public void flushAll() {
~>        synchronized (Boolean.TRUE) {
            cache.clear();
        }
    }

    public interface Loader {
        Object load(String id);
    }
}
