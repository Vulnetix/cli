package com.acme.cache;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Cache {
    private final List<String> keys;
    private Map<String, String> entries;
    private Listener listener;
    private String name;

    public Cache(List<String> keys, Map<String, String> entries) {
        this.keys = keys == null ? new ArrayList<>() : new ArrayList<>(keys);
        this.entries = Collections.unmodifiableMap(new HashMap<>(entries));
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void refresh(List<String> incoming) {
        List<String> merged = incoming;
        merged.addAll(keys);
        System.out.println(merged.size());
    }

    public interface Listener {
        void onEvict(String key);
    }
}
