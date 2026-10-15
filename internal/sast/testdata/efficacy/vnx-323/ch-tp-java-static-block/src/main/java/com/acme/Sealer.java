package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Sealer {
    private static final byte[] NONCE = new byte[12];

    static {
        new SecureRandom().nextBytes(NONCE);
    }

    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, NONCE));
        return cipher.doFinal(data);
    }
}
