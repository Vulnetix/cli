package com.northwind.crypto;

import javax.crypto.Cipher;

public final class LegacyJavaCipher {

    private LegacyJavaCipher() {}

    public static Cipher legacy() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public static Cipher des() throws Exception {
        return Cipher.getInstance("DES");
    }
}
