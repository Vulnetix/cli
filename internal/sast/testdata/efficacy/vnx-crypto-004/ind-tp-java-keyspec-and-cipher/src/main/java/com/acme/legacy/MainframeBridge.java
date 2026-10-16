package com.acme.legacy;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainframeBridge {
    public byte[] encrypt(byte[] raw, byte[] iv, byte[] data) throws Exception {
~>        SecretKeySpec key = new SecretKeySpec(raw, "DESede");
~>        Cipher c = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(data);
    }
}
