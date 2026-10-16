package com.acme.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class GoodEncryptor {
    private final SecureRandom random = new SecureRandom();
    private final SecretKey key;
    private byte[] iv = new byte[12];

    public GoodEncryptor(SecretKey key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] message) throws Exception {
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(message);
    }
}
