package com.acme.web;

import java.util.Locale;

public final class LinkValidator {
    public static String checkHomepage(String url) {
        String normalised = url.trim().toLowerCase(Locale.ROOT);
        if (normalised.startsWith("javascript:") || normalised.contains("javascript:")) {
            throw new IllegalArgumentException("bad link");
        }
        return url;
    }
}
