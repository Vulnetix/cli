package com.acme.web;

import java.util.regex.Pattern;

public final class XssFilter {

~>    private static final Pattern SCRIPT_TAG = Pattern.compile("<script(.*?)>(.*?)</script>");

    private XssFilter() {}

    public static String clean(String value) {
        if (value == null) {
            return null;
        }
        String out = SCRIPT_TAG.matcher(value).replaceAll("");
~>        out = out.replaceAll("<img[^>]+onerror[^>]*>", "");
        return out;
    }

    public static boolean looksLikeSqlInjection(String param) {
~>        return param.contains("union select") || param.contains("drop table");
    }
}
