package com.acme;

public class TokenCheck {
    public boolean matches(String storedToken, String presented) {
~>        return storedToken.regionMatches(0, presented, 0, 6);
    }

    public boolean sigOk(String expectedSignature, String providedSignature) {
~>        return expectedSignature.endsWith(providedSignature);
    }

    public boolean pin(String pinCode, String entered) {
~>        return pinCode.substring(0, 4).equals(entered);
    }
}
