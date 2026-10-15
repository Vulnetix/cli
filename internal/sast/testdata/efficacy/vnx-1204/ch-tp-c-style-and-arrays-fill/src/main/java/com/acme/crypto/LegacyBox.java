package com.acme.crypto;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class LegacyBox {
    public byte[] wrap(SecretKey key, byte[] data) throws Exception {
~>        byte iv[] = new byte[16];
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public byte[] wrapFixed(SecretKey key, byte[] data) throws Exception {
~>        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x01);
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        return c.doFinal(data);
    }
}
