package com.acme.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public final class LegacyEnvelope {
    private static final String TRANSFORM = "RSA/NONE/PKCS1Padding";

    public byte[] seal(PublicKey key, byte[] data) throws Exception {
~>        Cipher cipher = Cipher.getInstance(TRANSFORM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
