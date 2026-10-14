package com.acme;

import java.security.MessageDigest;

public class Verify {
    boolean check(byte[] expectedMac, byte[] providedMac) {
        return MessageDigest.isEqual(expectedMac, providedMac);
    }

    boolean present(String token) {
        return token != null && !token.equals("");
    }
}
