package com.acme.vault;

import javax.crypto.Cipher;

public class Docs {
    // Never use Cipher.getInstance("AES/ECB/PKCS5Padding"); it leaks block structure.
    /* old: alg + "/ECB/PKCS5Padding" */
    static final String WARNING = "Do not pass AES/ECB/NoPadding to Cipher.getInstance";

    public Cipher fromCaller(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }

    public Cipher chacha() throws Exception {
        return Cipher.getInstance("ChaCha20-Poly1305");
    }
}
