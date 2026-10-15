package com.example;

import java.util.HashMap;
import java.util.Map;

public class TokenCache {
    private static final String CACHE_LOCK = "token-cache";
    private final Map<String, String> tokens = new HashMap<>();

    public String refresh(String user) {
~>        synchronized ("refresh") {
            return tokens.get(user);
        }
    }

    public void evict(String user) {
~>        synchronized (user.intern()) {
            tokens.remove(user);
        }
    }

    public void clear() {
~>        synchronized(CACHE_LOCK) {
            tokens.clear();
        }
    }

    public void flag() {
~>        synchronized (Boolean.TRUE) {
            tokens.put("flag", "1");
        }
    }
}
