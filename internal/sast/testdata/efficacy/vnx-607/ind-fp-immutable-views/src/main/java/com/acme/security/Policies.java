package com.acme.security;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Policies {

    public static final Map<String, String> ROLE_ALIASES =
            Collections.unmodifiableMap(new HashMap<>(Map.of("admin", "root")));

    public static final List<String> TRUSTED = List.of("10.0.0.1", "10.0.0.2");

    public static final Set<String> SCOPES = Set.of("read", "write");

    public static final Map<String, Integer> WEIGHTS = Map.of("low", 1, "high", 3);

    public static final ImmutableMap<String, String> HEADERS = ImmutableMap.of("X-Frame-Options", "DENY");

    public static final ImmutableSet<String> METHODS = ImmutableSet.of("GET", "HEAD");

    public static final List<String> NONE = Collections.emptyList();

    // public static final Map<String, String> OLD = new HashMap<>();  (removed)

    private Policies() {
    }
}
