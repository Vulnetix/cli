package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Modern {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public SecretKey key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    public Cipher cipher() throws Exception {
        return Cipher.getInstance(TRANSFORMATION);
    }

    public Cipher chacha() throws Exception {
        return Cipher.getInstance("ChaCha20-Poly1305");
    }

    public Cipher descriptive() throws Exception {
        Cipher designated = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return designated;
    }
}
