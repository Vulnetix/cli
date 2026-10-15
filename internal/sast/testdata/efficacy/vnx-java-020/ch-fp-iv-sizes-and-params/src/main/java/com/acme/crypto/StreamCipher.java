package com.acme.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class StreamCipher {
    private static final int GCM_TAG_BITS = 128;
    private static final String IV_PROPERTY = "cipher.iv";
    private final byte[] iv;

    public StreamCipher(byte[] iv) {
        this.iv = iv.clone();
    }

    public Cipher open(SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.iv));
        return c;
    }

    public Cipher seal(SecretKey key, SecureRandom rnd) throws Exception {
        byte[] nonce = new byte[12];
        rnd.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS,
                nonce));
        return c;
    }
}
