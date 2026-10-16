package com.acme.sign;

public class MacCheck {
    public static boolean verify(byte[] expectedMac, byte[] providedMac) {
        if (expectedMac.length != providedMac.length) {
            return false;
        }
        for (int i = 0; i < expectedMac.length; i++) {
~>            if (expectedMac[i] != providedMac[i]) return false;
        }
        return true;
    }
}
