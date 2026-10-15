package com.acme;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    public byte[] encrypt(byte[] keyBytes, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(keyBytes));
        return c.doFinal(plain);
    }

    public byte[] encrypt2(SecretKeySpec key, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        IvParameterSpec iv = new IvParameterSpec(key.getEncoded());
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        return c.doFinal(plain);
    }

    public byte[] encrypt3(byte[] secretKey, byte[] plain) throws Exception {
~>        byte[] ivBytes = Arrays.copyOf(secretKey, 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new IvParameterSpec(ivBytes));
        return c.doFinal(plain);
    }
}
