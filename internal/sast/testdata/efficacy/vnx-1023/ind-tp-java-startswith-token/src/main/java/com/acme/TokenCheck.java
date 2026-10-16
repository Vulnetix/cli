package com.acme;

public class TokenCheck {
    public boolean matches(String expectedToken, String supplied) {
~>        return expectedToken.startsWith(supplied);
    }
}
