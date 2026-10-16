package com.acme.sign;

public class SigVerifier {
    static boolean checkSignature(byte[] a, byte[] b) {
        int i = 0;
        while (i < a.length) {
~>            if (a[i] != b[i]) {
                return false;
            }
            i++;
        }
        return true;
    }
}
