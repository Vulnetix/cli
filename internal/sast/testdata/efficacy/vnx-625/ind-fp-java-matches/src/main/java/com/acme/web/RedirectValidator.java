package com.acme.web;

public final class RedirectValidator {
    public static boolean isSafe(String url) {
        return url != null && url.matches("https://([a-z0-9-]+\\.)?acme\\.com(/.*)?");
    }
}
