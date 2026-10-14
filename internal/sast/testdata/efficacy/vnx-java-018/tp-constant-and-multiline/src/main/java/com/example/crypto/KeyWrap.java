package com.example.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class KeyWrap {
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    static final String RAW_RSA = "RSA/None/NoPadding";

    public byte[] wrap(PublicKey key, byte[] secret) throws Exception {
~>        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.WRAP_MODE, key);
        return cipher.doFinal(secret);
    }

    public byte[] wrapRaw(PublicKey key, byte[] secret) throws Exception {
~>        Cipher cipher = Cipher.getInstance(
                RAW_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(secret);
    }

    public Cipher inline() throws Exception {
~>        return Cipher.getInstance(
            "RSA/ECB/PKCS1Padding");
    }
}
