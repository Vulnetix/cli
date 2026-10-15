package com.acme.auth;

public class Webhook {
    public boolean verify(String signature, String computed) {
~>        return computed.substring(0, 12).equals(signature);
    }

    public boolean verifyPassword(String passwordHash, String candidate) {
~>        return candidate.equals(passwordHash.substring(0, candidate.length()));
    }
}
