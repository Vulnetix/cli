package com.acme.util;

public final class Numbers {
    public static Integer tryParse(String s) {
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException ignored) {
        }
        return null;
    }

    public static Long tryParseLong(String s) {
        try {
            return Long.valueOf(s);
        } catch (NumberFormatException expected) {}
        return null;
    }
}
