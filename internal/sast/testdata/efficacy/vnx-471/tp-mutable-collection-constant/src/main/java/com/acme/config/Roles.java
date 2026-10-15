package com.acme.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Roles {
~>    public static final List<String> ADMINS = new ArrayList<>();
~>    public static final Map<String, Integer> LIMITS = new HashMap<String, Integer>();
~>    public static final Set<String> BLOCKED =
            new java.util.HashSet<>();

    static {
        ADMINS.add("alice");
        LIMITS.put("upload", 10);
    }
}
