package com.acme.web;

import java.util.regex.Pattern;

public final class XssFilter {
~>    private static final Pattern SCRIPT = Pattern.compile("<script>(.*?)</script>");

    public static String clean(String value) {
~>        String v = value.replaceAll("<script[^>]*>", "");
~>        v = v.replace("javascript:", "");
        return SCRIPT.matcher(v).replaceAll("");
    }

    public static boolean suspicious(String q) {
~>        return q.contains("union select") || q.contains("<script");
    }
}
