package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PayloadCipher {
    private final byte[] keyBytes;

    public PayloadCipher(byte[] keyBytes) {
        this.keyBytes = keyBytes;
    }

    public byte[] encrypt(byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(keyBytes));
        return cipher.doFinal(plain);
    }
}
