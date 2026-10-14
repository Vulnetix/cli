package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Sealer {
    private static final byte[] NONCE = new byte[12];

    public byte[] zero(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
        return c.doFinal(data);
    }

    public byte[] gcm(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, NONCE));
        return c.doFinal(data);
    }

    public byte[] unfilled(SecretKey key, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public GCMParameterSpec gcmLiteral() {
~>        return new GCMParameterSpec(128, "nonce-123456".getBytes());
    }
}
