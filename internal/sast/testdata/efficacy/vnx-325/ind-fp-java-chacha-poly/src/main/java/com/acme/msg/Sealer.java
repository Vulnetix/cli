package com.acme.msg;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public final class Sealer {
    public static byte[] seal(SecretKey key, byte[] nonce, byte[] msg) throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        return c.doFinal(msg);
    }
}
