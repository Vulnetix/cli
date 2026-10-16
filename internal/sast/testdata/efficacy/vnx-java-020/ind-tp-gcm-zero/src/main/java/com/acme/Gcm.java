package com.acme;
import javax.crypto.spec.GCMParameterSpec;
public class Gcm {
    GCMParameterSpec spec() {
        byte[] nonce = new byte[12];
~>        return new GCMParameterSpec(128, nonce);
    }
}
