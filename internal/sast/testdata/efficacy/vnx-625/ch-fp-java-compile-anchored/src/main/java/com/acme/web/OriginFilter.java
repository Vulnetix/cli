package com.acme.web;

import java.util.regex.Pattern;

public class OriginFilter {
    private static final Pattern ORIGIN =
        Pattern.compile("^https://([a-z0-9-]+\\.)?acme\\.com(:\\d+)?$");

    public boolean allowed(String origin) {
        return ORIGIN.matcher(origin).matches()
            && origin.matches("https://[a-z]+\\.acme\\.com");
    }
}
