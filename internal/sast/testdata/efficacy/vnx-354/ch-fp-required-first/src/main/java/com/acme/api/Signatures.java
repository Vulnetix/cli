package com.acme.api;

import java.security.MessageDigest;
import java.util.Objects;

public class Signatures {
    public void check(byte[] signature, byte[] expected) {
        Objects.requireNonNull(signature, "signature header missing");
        if (signature != null && !MessageDigest.isEqual(signature, expected)) {
            throw new SecurityException("bad signature");
        }
    }

    public boolean prefixed(String header) {
        return header.startsWith("sha256=");
    }
}
