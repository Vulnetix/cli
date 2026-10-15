package com.example;

import java.util.*;

public class Roles {
    public static final Map<String, String> PERMISSIONS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("admin", "rw");
        PERMISSIONS = Collections.unmodifiableMap(m);
    }

    public static final List<String> HOSTS = Collections.unmodifiableList(new ArrayList<>(List.of("a")));
    public static final Set<String> NAMES = Set.of("a", "b");
    public static final List<String> EMPTY = Collections.emptyList();
    public static final Map<String, Integer> CODES = Map.of("ok", 200);
}
