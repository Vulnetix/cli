package com.acme.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

public class Pbe {
    private static final byte[] SALT = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08};
    private static final String LABEL = "envelope-v1";
    private final SecureRandom rng = new SecureRandom();

    public PBEParameterSpec params() {
        return new PBEParameterSpec(SALT, 65536);
    }

    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        byte[] nonce = new byte[12];
        rng.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        c.updateAAD(LABEL.getBytes());
        return c.doFinal(data);
    }
}
