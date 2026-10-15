package com.acme;

import java.util.Arrays;

public class Hook {
    boolean ok(String signatureHeader, String expectedSignature, byte[] computedMac, byte[] receivedMac) {
~>        if (!expectedSignature.equals(signatureHeader)) return false;
~>        return Arrays.equals(computedMac, receivedMac);
    }
}
