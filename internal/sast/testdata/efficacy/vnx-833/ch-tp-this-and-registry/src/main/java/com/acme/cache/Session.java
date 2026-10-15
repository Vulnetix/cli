package com.acme.cache;

import java.util.Map;

public class Session {
    private static final Map<String, Session> REGISTRY = new java.util.HashMap<>();
    private String id;

    public void rename(String next) {
        synchronized(this) {
~>            synchronized(REGISTRY) {
                REGISTRY.remove(id);
                id = next;
                REGISTRY.put(id, this);
            }
        }
    }

    public static void expireAll() {
        synchronized (REGISTRY) {
            for (Session s : REGISTRY.values()) {
                s.touch();
            }
        }
    }

    public void evict() {
        synchronized (REGISTRY) {
~>            synchronized (this) {
                REGISTRY.remove(id);
            }
        }
    }

    private void touch() {}
}
