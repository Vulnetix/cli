package com.acme;

import javax.crypto.Cipher;

public class Box {
    private static final String TRANSFORM = "AES/ECB/PKCS5Padding";

    byte[] seal(byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance(TRANSFORM);
        return c.doFinal(d);
    }
}
