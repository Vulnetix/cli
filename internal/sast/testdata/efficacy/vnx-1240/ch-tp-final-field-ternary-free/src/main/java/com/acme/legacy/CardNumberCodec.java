package com.acme.legacy;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CardNumberCodec {
    private static final String TRANSFORMATION = "AES";
    private static final String PROVIDER = "SunJCE";

    private final SecretKey key;

    public CardNumberCodec(SecretKey key) {
        this.key = key;
    }

    public byte[] encode(byte[] pan) throws Exception {
~>        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }
}
