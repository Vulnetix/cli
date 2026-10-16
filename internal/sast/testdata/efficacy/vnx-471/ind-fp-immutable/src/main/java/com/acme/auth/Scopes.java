package com.acme.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Scopes {
    public static final List<String> SCOPES = List.of("read", "write");
    public static final Set<String> ROLES = Set.of("admin", "user");
    public static final Map<String, Integer> LIMITS = Map.of("login", 5);
    public static final List<String> HOSTS =
        Collections.unmodifiableList(Arrays.asList("a.example", "b.example"));
}
