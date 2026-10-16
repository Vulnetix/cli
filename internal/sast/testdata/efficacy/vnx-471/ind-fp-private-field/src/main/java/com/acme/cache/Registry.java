package com.acme.cache;

import java.util.HashMap;
import java.util.Map;

public class Registry {
    private static final Map<String, Object> ENTRIES = new HashMap<>();
    static final Map<String, Object> PACKAGE_ENTRIES = new HashMap<>();
    public final Map<String, Object> perInstance = new HashMap<>();

    public static Object get(String k) {
        return ENTRIES.get(k);
    }
}
