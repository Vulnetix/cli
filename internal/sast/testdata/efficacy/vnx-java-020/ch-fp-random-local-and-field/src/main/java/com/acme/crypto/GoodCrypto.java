package com.acme.crypto;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class GoodCrypto {
    private static final int IV_LEN = 12;
    private final SecureRandom random = new SecureRandom();
    private final byte[] cbcIv = new byte[16];

    public byte[] gcm(SecretKey key, byte[] data) throws Exception {
        byte[] nonce = new byte[IV_LEN];
        random.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        return ByteBuffer.allocate(IV_LEN + data.length + 16).put(nonce).put(c.doFinal(data)).array();
    }

    public byte[] cbc(SecretKey key, byte[] data) throws Exception {
        random.nextBytes(cbcIv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(cbcIv));
        return c.doFinal(data);
    }
}
