package com.acme.config;

import java.util.HashMap;
import java.util.Map;

public final class Limits {
~>    public static final Map<String, Integer> RATE_LIMITS = new HashMap<String, Integer>();

    static {
        RATE_LIMITS.put("login", 5);
    }
}
