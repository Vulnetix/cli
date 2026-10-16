package com.acme.util;

public final class Sanitizer {
    public static String path(String path) {
        return path.replace("../", "");
    }

    public static String html(String s) {
        String out = s.replaceAll("<script>", "");
        return out.replaceAll("(?i)<script.*?>", "");
    }
}
