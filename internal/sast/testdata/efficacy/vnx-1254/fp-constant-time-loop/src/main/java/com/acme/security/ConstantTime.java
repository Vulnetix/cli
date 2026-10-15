package com.acme.security;

public final class ConstantTime {
    public static boolean verifyMac(byte[] expectedMac, byte[] providedMac) {
        if (expectedMac.length != providedMac.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < expectedMac.length; i++) {
            diff |= expectedMac[i] ^ providedMac[i];
        }
        return diff == 0;
    }
}
