package com.acme;

final class SignatureCheck {
    boolean matches(byte[] expected, byte[] supplied) {
        for (int i = 0; i < expected.length; i++) {
~>            if (expected[i] != supplied[i]) return false;
        }
        return true;
    }
}
