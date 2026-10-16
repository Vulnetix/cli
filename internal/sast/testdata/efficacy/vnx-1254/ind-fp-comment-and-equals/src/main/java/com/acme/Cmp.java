package com.acme;

import java.security.MessageDigest;
import java.util.Arrays;

class Cmp {
    // for (int i = 0; i < expectedMac.length; i++) { if (expectedMac[i] != providedMac[i]) return false; }
    boolean ok(byte[] hmac, byte[] other) {
        return MessageDigest.isEqual(hmac, other);
    }

    int indexOfDiff(String token, String other) {
        for (int i = 0; i < token.length(); i++) {
            if (token.charAt(i) != other.charAt(i)) {
                return i;
            }
        }
        return -1;
    }
}
