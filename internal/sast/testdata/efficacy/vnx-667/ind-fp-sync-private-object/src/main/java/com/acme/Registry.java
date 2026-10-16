package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Registry {
    private final Object mutex = new Object();
    private final Map<String, String> map = new HashMap<>();

    public void put(String k, String v) {
        synchronized (mutex) {
            map.put(k, v);
        }
    }

    public void clear() {
        synchronized (this) {
            map.clear();
        }
    }

    public static void reset() {
        synchronized (Registry.class) {
            System.gc();
        }
    }

    // synchronized (LOCK) with a "LOCK" string is a bad idea
    private static final String DOC = "synchronized (\"x\") { }";
}
