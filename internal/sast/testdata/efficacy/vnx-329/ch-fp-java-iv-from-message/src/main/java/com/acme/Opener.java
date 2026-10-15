package com.acme;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Opener {
    public byte[] open(byte[] keyBytes, byte[] message) throws Exception {
        byte[] iv = Arrays.copyOfRange(message, 0, 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
        return c.doFinal(Arrays.copyOfRange(message, 16, message.length));
    }
}
