package com.acme.config;

import java.util.Map;

public class EnvConfig {
    private final Map<String, String> env;

    public EnvConfig() {
        Map<String, String> source = System.getenv();
        this.env = source;
    }

    public static Map<String, String> snapshot() {
        return System.getenv();
    }
}
