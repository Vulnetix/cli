package com.acme.cache;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CacheHolder {

    private static final Map<String, Object> CACHE = new ConcurrentHashMap<>();

    static final List<String> PACKAGE_LISTENERS = new ArrayList<>();

    protected static final Map<String, String> SUBCLASS_HOOKS = new HashMap<>();

    public final Map<String, Object> perInstance = new HashMap<>();

    public static Map<String, Object> scratch = new HashMap<>();

    public static final Map<String, String> REGISTRY;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("default", "lru");
        REGISTRY = Collections.unmodifiableMap(m);
    }

    public static Object get(String key) {
        return CACHE.get(key);
    }
}
