package com.example.crypto;

import javax.crypto.Cipher;

public class TokenCipher {
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    Cipher create() throws Exception {
~>        return Cipher.getInstance(TRANSFORMATION);
    }
}
