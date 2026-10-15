package com.acme.crypto;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Decryptor {
    public byte[] gcm(SecretKey key, byte[] message) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, message, 0, 12));
        return c.doFinal(message, 12, message.length - 12);
    }

    public byte[] cbc(SecretKey key, byte[] message) throws Exception {
        byte[] iv = Arrays.copyOfRange(message, 0, 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(message, 16, message.length - 16);
    }

    public IvParameterSpec reuse(Cipher enc) {
        String note = "new IvParameterSpec(\"0000000000000000\".getBytes())";
        return new IvParameterSpec(enc.getIV());
    }
}
