package com.example.crypto;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class LegacyCrypto {
    private static final byte[] IV = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            (byte) 0x88, (byte) 0x99, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    private static final String IV_TEXT = "static-iv-value!";
    byte[] ivBytes = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
~>        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return c.doFinal(data);
    }

    public IvParameterSpec text() {
        byte[] iv = IV_TEXT.getBytes();
~>        return new IvParameterSpec(iv);
    }

    public AlgorithmParameterSpec field() {
~>        AlgorithmParameterSpec spec = new IvParameterSpec(ivBytes);
        return spec;
    }
}
