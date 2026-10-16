package com.acme;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class Live {
    private final Map<String, Conn> conns = new ConcurrentHashMap<>();

    void reap() {
        for (Map.Entry<String, Conn> e : conns.entrySet()) {
            if (e.getValue().idle()) {
                conns.remove(e.getKey());
            }
        }
    }
}
