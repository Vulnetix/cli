package com.acme.util;

public final class Names {
    static boolean blank(String name) {
~>        return name == null | name.trim().isEmpty();
    }

    static boolean missing(String[] parts) {
~>        if (parts == null | parts[0].isEmpty()) {
            return true;
        }
        return false;
    }

    static boolean invalid(Object a, String b) {
~>        return a == null || b == null | b.length() == 0;
    }
}
