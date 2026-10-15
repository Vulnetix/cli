package com.acme.config;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class Registry {
    public static final Logger LOG = Logger.getLogger(Registry.class.getName());
    protected static final Map<String, Object> BEANS = new HashMap<>();
    public final Map<String, Object> instanceScoped = new HashMap<>();
    public static Map<String, Object> notFinal = new HashMap<>();
    // public static final Map<String, Object> OLD = new HashMap<>();
}
