package com.acme.security;

public class WebhookVerifier {
    public boolean verify(byte[] expectedMac, byte[] providedMac) {
        if (expectedMac.length != providedMac.length) {
            return false;
        }
        for (int i = 0; i < expectedMac.length; i++) {
~>            if (expectedMac[i] != providedMac[i]) return false;
        }
        return true;
    }
}
