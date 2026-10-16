package com.acme.security;

import javax.servlet.http.HttpServletRequest;

public final class RefererCsrfFilter {
    private final String host;

    public RefererCsrfFilter(String host) {
        this.host = host;
    }

    public boolean isSameSite(HttpServletRequest request) {
        String referer = request.getHeader("Referer");
~>        return referer != null && referer.contains(host);
    }
}
