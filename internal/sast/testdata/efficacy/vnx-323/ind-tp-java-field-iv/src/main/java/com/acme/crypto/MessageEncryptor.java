package com.acme.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MessageEncryptor {
    private final SecretKey key;
    private final byte[] iv = new byte[12];

    public MessageEncryptor(SecretKey key) {
        this.key = key;
        new SecureRandom().nextBytes(iv);
    }

    public byte[] encrypt(byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(message);
    }
}
