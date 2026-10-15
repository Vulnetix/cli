package com.acme.util;

public final class Ids {
    public static String compact(String uuid) {
        return uuid.replace("-", "").replaceAll("\\s+", "");
    }

    public static String encode(String s) {
        return s.replace("<", "&lt;").replace("../", "_");
    }
}
