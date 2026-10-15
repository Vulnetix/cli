package com.acme.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Settings {
    public static final String NAME = "acme";
    public static final int MAX_RETRIES = 3;
    public static final String[] EMPTY = new String[0];
    public static final String[] NONE = {};
    public static final List<String> SCOPES = List.of("read", "write");
    public static final Set<String> ACCOUNTS = Set.of("tom", "jerry");
    public static final Map<String, Integer> LIMITS = Collections.unmodifiableMap(new HashMap<>());
    public static final List<String> COPY = List.copyOf(Collections.emptyList());
    private static final String[] SECRETS = {"a", "b"};
    static final List<String> PACKAGE_LOCAL = new java.util.ArrayList<>();
    public final String[] perInstance = {"x"};
    public static final Map<String, String> LATER;

    static {
        LATER = Collections.emptyMap();
    }
}
