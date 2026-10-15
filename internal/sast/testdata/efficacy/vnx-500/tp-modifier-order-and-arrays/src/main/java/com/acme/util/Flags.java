package com.acme.util;

public class Flags {
~>    static public boolean debug = false;
~>    public volatile static long lastSeen = 0L;
~>    public static String[] trustedHosts = {"a.example.com", "b.example.com"};
~>    @Deprecated public static int legacyMode = 1;
}
