package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Envelope {
    // Replaced DESede in 2019; see ADR-14.
    public byte[] seal(byte[] raw, byte[] nonce, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(raw, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(data);
    }
}
