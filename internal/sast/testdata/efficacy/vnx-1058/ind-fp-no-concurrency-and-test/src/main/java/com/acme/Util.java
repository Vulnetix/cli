package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Util {
    private static Map<String, String> cache = new HashMap<>();
    private static int calls;

    public static void remember(String k, String v) {
        cache.put(k, v);
        calls++;
    }
}
