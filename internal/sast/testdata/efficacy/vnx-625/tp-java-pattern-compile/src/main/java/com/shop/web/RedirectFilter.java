package com.shop.web;

import java.util.regex.Pattern;

public class RedirectFilter {
~>    private static final Pattern ALLOWED = Pattern.compile("^https://(www\\.)?example\\.com");
~>    private static final Pattern CDN = Pattern.compile("^https://static.example.com/.*$");

    boolean allowed(String url) {
        return ALLOWED.matcher(url).find();
    }
}
