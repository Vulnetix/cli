package com.acme.config;

import java.util.List;
import java.util.Map;

public class Codes {
~>    final public static Map<String, Integer> STATUS = new java.util.HashMap<String, Integer>() {{
        put("ok", 200);
        put("missing", 404);
    }};

~>    public static final Map<Class<?>, List<String>> HANDLERS = new java.util.concurrent.ConcurrentHashMap<>();
}
