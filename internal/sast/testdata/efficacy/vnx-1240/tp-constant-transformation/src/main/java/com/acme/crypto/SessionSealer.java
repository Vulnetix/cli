package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public final class SessionSealer {
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String MODE_SAFE = "AES/GCM/NoPadding";

    public byte[] seal(SecretKey key, byte[] session) throws Exception {
~>        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(session);
    }

    public byte[] sealSafe(SecretKey key, byte[] session) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE_SAFE);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(session);
    }
}
