package com.example.vault;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {
    private final Random rnd = new Random();

    byte[] enc(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        byte[] iv = new byte[16];
~>        rnd.nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(in);
    }

    byte[] enc2(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        byte[] nonce = new byte[16];
~>        new java.util.Random(System.currentTimeMillis()).nextBytes(nonce);
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        return c.doFinal(in);
    }
}
