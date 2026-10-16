package com.acme;

import java.util.HashMap;
import java.util.Map;

public class TokenCache {
    private static final String CACHE_LOCK = "token-cache";
    private final Map<String, String> tokens = new HashMap<>();

    public String get(String key) {
~>        synchronized (CACHE_LOCK) {
            return tokens.get(key);
        }
    }

    public void put(String key, String value) {
~>        synchronized (CACHE_LOCK) {
            tokens.put(key, value);
        }
    }
}
