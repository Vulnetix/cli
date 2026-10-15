package com.acme.web;

public class TokenFilter {
    private String expectedToken;

    boolean matches(String presented) {
~>        return presented == expectedToken;
    }

    boolean sameUser(String a, String b) {
        String left = a.trim();
        String right = b.trim();
~>        if (left != right) {
            return false;
        }
        return true;
    }
}
