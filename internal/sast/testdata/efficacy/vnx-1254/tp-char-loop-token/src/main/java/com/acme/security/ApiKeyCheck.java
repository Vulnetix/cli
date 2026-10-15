package com.acme.security;

public class ApiKeyCheck {
    public boolean matches(String storedToken, String presented) {
        if (storedToken.length() != presented.length()) {
            return false;
        }
        for (int i = 0; i < storedToken.length(); i++) {
~>            if (storedToken.charAt(i) != presented.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
