package com.acme.web;

public class TokenGuard {
    boolean matches(String storedToken, String presented) {
        for (int i = 0; i < storedToken.length(); i++) {
~>            if (storedToken.charAt(i) != presented.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
