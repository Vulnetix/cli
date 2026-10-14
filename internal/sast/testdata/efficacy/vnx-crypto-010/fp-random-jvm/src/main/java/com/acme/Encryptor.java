package com.acme;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class Encryptor {
    private static final SecureRandom RANDOM = new SecureRandom();

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return ByteBuffer.allocate(iv.length + data.length).put(iv).put(cipher.doFinal(data)).array();
    }

    public byte[] decrypt(SecretKey key, byte[] blob) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob);
        byte[] iv = new byte[12];
        buf.get(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(blob, 12, blob.length - 12);
    }

    public byte[] cbc(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        IvParameterSpec spec = new IvParameterSpec(iv);
        return cipher.doFinal(data);
    }

    public byte[] derive(char[] password) throws Exception {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
