package com.acme.web;

public final class LinkValidator {
    public static String checkHomepage(String url) {
~>        if (url.contains("javascript:")) {
            throw new IllegalArgumentException("bad link");
        }
        return url;
    }
}
