package com.acme.api;

public final class Strings {

    @Deprecated
    public static String trimAll(String s) {
        return s == null ? null : s.trim();
    }

    @Deprecated(forRemoval = true)
    @SuppressWarnings("unused")
    static int legacyHash(String s) {
        return s.hashCode();
    }
}
