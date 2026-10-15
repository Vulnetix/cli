package com.acme.session;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionStore {
    private final Map<String, Long> expiry = new ConcurrentHashMap<>();

    public void touch(String id) {
~>        expiry.put(id, System.currentTimeMillis() + 86_400_000L);
    }

    public boolean expired(String id, long now) {
        Long at = expiry.get(id);
~>        return at == null || now - at > 86_400_000L;
    }

    public long remaining(String id, long now) {
~>        return Math.max(0, expiry.getOrDefault(id, now) + 86_400_000L - now);
    }
}
