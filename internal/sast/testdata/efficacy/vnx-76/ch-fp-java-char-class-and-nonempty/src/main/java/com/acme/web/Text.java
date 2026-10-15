package com.acme.web;

public final class Text {
    private Text() {}

    public static String noBrackets(String s) {
        return s.replaceAll("[<>]", "");
    }

    public static String breaks(String s) {
        return s.replace("<br>", "\n");
    }

    public static String spaces(String s) {
        return s.replaceAll("\\s+", "");
    }
}
