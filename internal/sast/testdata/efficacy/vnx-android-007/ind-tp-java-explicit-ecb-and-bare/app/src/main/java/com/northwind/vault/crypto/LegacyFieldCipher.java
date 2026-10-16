package com.northwind.vault.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class LegacyFieldCipher {

    private final SecretKeySpec key;

    public LegacyFieldCipher(byte[] rawKey) {
        this.key = new SecretKeySpec(rawKey, "AES");
    }

    public byte[] encrypt(String plain) throws GeneralSecurityException {
~>        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(byte[] data) throws GeneralSecurityException {
~>        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
    }
}
