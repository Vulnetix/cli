package com.acme.crypto;

import javax.crypto.Cipher;

public class TokenCipher {
    private static final String ALGO = "AES";
    private static final String MODE = ALGO + "/ECB/PKCS5Padding";

    public Cipher build() throws Exception {
~>        return Cipher.getInstance(MODE);
    }
}
