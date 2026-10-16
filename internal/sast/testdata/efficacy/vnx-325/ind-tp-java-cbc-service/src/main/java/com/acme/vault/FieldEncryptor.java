package com.acme.vault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FieldEncryptor {
~>    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public FieldEncryptor(SecretKey key) {
        this.key = key;
    }

    public String encrypt(String plain) throws GeneralSecurityException {
        byte[] iv = new byte[16];
        random.nextBytes(iv);
~>        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }
}
