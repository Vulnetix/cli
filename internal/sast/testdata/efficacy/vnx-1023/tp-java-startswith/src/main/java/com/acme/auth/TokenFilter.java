package com.acme.auth;

import javax.servlet.http.HttpServletRequest;

public class TokenFilter {
    private final String expectedToken;

    public TokenFilter(String expectedToken) {
        this.expectedToken = expectedToken;
    }

    public boolean allowed(HttpServletRequest request) {
        String supplied = request.getHeader("X-Token");
~>        return expectedToken.startsWith(supplied);
    }

    public boolean pinOk(String storedPin, String givenPin) {
~>        return storedPin.regionMatches(0, givenPin, 0, givenPin.length());
    }
}
