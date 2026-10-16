package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class FieldEncryptor {
    private final SecretKeySpec key;

    public FieldEncryptor(byte[] raw) {
        this.key = new SecretKeySpec(raw, "AES");
    }

    public byte[] encrypt(byte[] value) throws Exception {
~>        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(value);
    }

    public byte[] decrypt(byte[] value) throws Exception {
~>        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(value);
    }
}
