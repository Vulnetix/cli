package com.acme.config;

import java.util.HashMap;
import java.util.Map;

public class Settings {
~>    public static String adminEmail = "ops@example.com";
~>    public static int maxUploadMb;
~>    public static Map<String, String> overrides = new HashMap<>();
~>    public static Settings INSTANCE;

    private Settings() {
    }
}
