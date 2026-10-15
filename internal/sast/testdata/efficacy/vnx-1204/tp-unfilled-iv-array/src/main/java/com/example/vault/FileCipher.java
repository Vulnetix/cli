package com.example.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileCipher {
    public byte[] encrypt(byte[] key, byte[] plain) throws Exception {
~>        byte[] iv = new byte[16];
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec =
                new javax.crypto.spec.IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, k, ivSpec);
        return cipher.doFinal(plain);
    }

    public byte[] seal(Cipher cipher, SecretKeySpec k, byte[] plain) throws Exception {
~>        final byte[] nonce = new byte[GCM_IV_LENGTH];
        cipher.init(Cipher.ENCRYPT_MODE, k, new javax.crypto.spec.GCMParameterSpec(128, nonce));
        return cipher.doFinal(plain);
    }

    private static final int GCM_IV_LENGTH = 12;
}
