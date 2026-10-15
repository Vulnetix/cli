package com.acme;

public final class Zip {
    static boolean valid(String s) {
        return s.matches("[0-9]{5}");
    }

    static boolean valid2(String s) {
        return java.util.regex.Pattern.matches("[a-z]+", s);
    }
}
