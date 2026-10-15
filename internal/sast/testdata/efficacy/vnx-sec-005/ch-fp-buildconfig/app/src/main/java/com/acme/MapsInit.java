package com.acme;

public class MapsInit {
    static String key() {
        return BuildConfig.MAPS_API_KEY;
    }
    static boolean looksValid(String k) {
        return k.startsWith("AIza") && k.length() == 39;
    }
}
