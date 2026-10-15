package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Registry {
    private final Map<String, Object> entries = new HashMap<>();
    private final Object[] slots = new Object[8];

    public void put(String k, Object v) {
        synchronized (entries) {
            entries.put(k, v);
        }
    }
}
