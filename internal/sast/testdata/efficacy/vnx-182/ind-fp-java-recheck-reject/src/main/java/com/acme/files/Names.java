package com.acme.files;

public final class Names {

    public static String clean(String input) {
        String name = input.replace("../", "");
        if (name.contains("../")) {
            throw new IllegalArgumentException("invalid name");
        }
        return name;
    }
}
