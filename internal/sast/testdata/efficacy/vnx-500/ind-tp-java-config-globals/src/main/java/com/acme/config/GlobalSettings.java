package com.acme.config;

public class GlobalSettings {
~>    public static String adminEmail = "ops@example.com";
~>    static public boolean debug = false;
~>    public volatile static int maxRetries = 3;
    @Deprecated
~>    public static String[] trustedHosts = {"a.example.com", "b.example.com"};
~>    public static String dataDir;

    private GlobalSettings() {}
}
