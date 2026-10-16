package com.acme.sign;

import java.security.MessageDigest;

public class Good {
    static boolean hmacOk(byte[] expectedMac, byte[] providedMac) {
        return MessageDigest.isEqual(expectedMac, providedMac);
    }

    static boolean tokenOk(String storedToken, String presented) {
        if (storedToken.length() != presented.length()) return false;
        int diff = 0;
        for (int i = 0; i < storedToken.length(); i++) {
            diff |= storedToken.charAt(i) ^ presented.charAt(i);
        }
        return diff == 0;
    }

    static int firstDifference(byte[] digestA, byte[] digestB) {
        for (int i = 0; i < digestA.length; i++) {
            if (digestA[i] != digestB[i]) return i;
        }
        return -1;
    }
}
