package com.acme;

import javax.crypto.Cipher;

public class Rsa {
    private static final String ALG = "RSA/ECB/PKCS1Padding";

    Cipher a() throws Exception {
~>        return Cipher.getInstance(ALG);
    }

    Cipher b() throws Exception {
~>        return Cipher.getInstance(
            "RSA/NONE/NoPadding");
    }
}
