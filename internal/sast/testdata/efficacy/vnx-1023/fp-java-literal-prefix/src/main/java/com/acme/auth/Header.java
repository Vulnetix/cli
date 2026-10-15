package com.acme.auth;

import java.security.MessageDigest;

public class Header {
    private static final String SIG_PREFIX = "sha256=";

    public boolean verify(String signature, byte[] expected) {
        if (!signature.startsWith(SIG_PREFIX)) {
            return false;
        }
        if (signature.startsWith("sha1=")) {
            return false;
        }
        String shown = signature.substring(0, 6) + "...";
        return MessageDigest.isEqual(signature.substring(7).getBytes(), expected);
    }

    public boolean isBearer(String authHeader, String token) {
        return authHeader.startsWith("Bearer ") && token.length() > 0;
    }
}
