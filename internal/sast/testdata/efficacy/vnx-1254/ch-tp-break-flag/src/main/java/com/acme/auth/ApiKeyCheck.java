package com.acme.auth;

public class ApiKeyCheck {
    public boolean matches(byte[] apiKey, byte[] presented) {
        if (apiKey.length != presented.length) {
            return false;
        }
        boolean ok = true;
        for (int i = 0; i < apiKey.length; i++) {
~>            if (apiKey[i] != presented[i]) {
                ok = false;
                break;
            }
        }
        return ok;
    }
}
