package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Cache2 {
    private Map<String, String> cache;
    private final Map<String, String> other = new HashMap<>();
    private int count;

    public String get(String k) {
        if (cache == null) cache = new HashMap<>();
        return cache.get(k) + other.get(k);
    }
}
