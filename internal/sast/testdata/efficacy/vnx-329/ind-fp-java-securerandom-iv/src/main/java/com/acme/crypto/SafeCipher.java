package com.acme.crypto;

import java.security.KeyStore;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SafeCipher {
    private final SecureRandom random = new SecureRandom();

    public byte[] encrypt(KeyStore keystore, char[] pass, byte[] plain) throws Exception {
        SecretKey key = (SecretKey) keystore.getKey("data", pass);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plain);
    }
}
