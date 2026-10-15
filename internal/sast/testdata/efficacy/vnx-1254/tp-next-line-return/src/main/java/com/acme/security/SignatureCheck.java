package com.acme.security;

public final class SignatureCheck {
    static boolean checkSignature(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        int idx = 0;
        while (idx < n) {
~>            if (a[idx] != b[idx])
                return false;
            idx++;
        }
        return a.length == b.length;
    }
}
