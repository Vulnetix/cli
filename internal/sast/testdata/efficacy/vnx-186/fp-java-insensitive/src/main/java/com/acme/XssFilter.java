package com.acme;

import java.util.regex.Pattern;

final class XssFilter {
    private static final Pattern SCRIPT = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL = Pattern.compile("(?i)^javascript:");

    static String clean(String v) {
        String r = v.replaceAll("(?i)<script[^>]*>", "");
        return SCRIPT.matcher(r).replaceAll("");
    }

    static boolean suspicious(String q) {
        return q.toLowerCase().contains("<script");
    }
}
