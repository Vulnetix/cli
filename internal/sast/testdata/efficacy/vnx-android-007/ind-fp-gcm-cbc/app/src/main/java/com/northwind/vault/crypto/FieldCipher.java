package com.northwind.vault.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public final class FieldCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private final SecureRandom random = new SecureRandom();

    public byte[] seal(SecretKey key, byte[] plain) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plain);
    }

    public byte[] legacyCbc(SecretKey key, byte[] iv, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
