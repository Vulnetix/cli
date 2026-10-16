package com.acme;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Gcm {
    public byte[] seal(SecretKey key, byte[] plain) throws Exception {
~>        byte[] iv = new byte[12];
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(plain);
    }
}
