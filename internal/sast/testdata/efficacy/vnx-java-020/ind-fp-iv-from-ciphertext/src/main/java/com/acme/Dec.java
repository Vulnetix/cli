package com.acme;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
public class Dec {
    Object a(byte[] msg) { return new IvParameterSpec(msg, 0, 16); }
    Object b(byte[] msg) {
        byte[] n = java.util.Arrays.copyOfRange(msg, 0, 12);
        return new GCMParameterSpec(128, n);
    }
}
