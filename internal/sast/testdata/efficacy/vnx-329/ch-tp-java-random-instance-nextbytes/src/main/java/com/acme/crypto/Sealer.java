package com.acme.crypto;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Sealer {
    private final Random rnd = new Random();

    public byte[] seal(byte[] key, byte[] plain) throws Exception {
        byte[] ivBytes = new byte[16];
~>        rnd.nextBytes(ivBytes);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(ivBytes));
        return c.doFinal(plain);
    }
}
