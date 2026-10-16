package com.acme.security;

import java.util.regex.Pattern;

public final class OriginFilter {
~>    private static final Pattern ALLOWED = Pattern.compile("^https://([a-z0-9-]+\\.)?acme\\.com");

    public static boolean allowed(String origin) {
        return origin != null && ALLOWED.matcher(origin).find();
    }
}
