package com.acme;

import java.security.MessageDigest;

public class Safe {
    static final String SIG_PREFIX = "sha256=";

    boolean hasScheme(String sig) {
        return sig.startsWith(SIG_PREFIX);
    }

    boolean auth(String token) {
        return token.startsWith("Bearer ");
    }

    boolean full(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    String shorten(String name) {
        return name.substring(0, 3).equals("abc") ? "x" : "y";
    }

    String log() {
        return "password.startsWith(input) is not used";
    }
}
