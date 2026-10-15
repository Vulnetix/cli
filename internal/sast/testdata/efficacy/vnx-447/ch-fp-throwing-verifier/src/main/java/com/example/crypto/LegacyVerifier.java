package com.example.crypto;

public class LegacyVerifier {

    public boolean verifySignature(byte[] data, byte[] sig) {
        throw new UnsupportedOperationException("legacy signatures are no longer accepted");
    }
}
