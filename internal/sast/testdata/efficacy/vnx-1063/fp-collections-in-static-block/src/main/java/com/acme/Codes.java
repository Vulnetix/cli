package com.acme;

import java.util.*;

public final class Codes {
    private static final Map<Integer, String> NAMES;
    private static final List<String> ORDER;

    static {
        Map<Integer, String> m = new HashMap<>();
        m.put(200, "OK");
        NAMES = Collections.unmodifiableMap(m);
        ORDER = new ArrayList<>(List.of("a", "b"));
        Set<String> seen = new LinkedHashSet<String>();
        StringBuilder sb = new StringBuilder();
        Object lock = new Object();
        int[] table = new int[256];
        if (NAMES.isEmpty()) throw new IllegalStateException("empty");
    }
}
