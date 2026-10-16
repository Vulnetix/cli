package com.acme.vault;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Modern {
    public byte[] gcm(SecretKey key, byte[] data) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    public byte[] wrap(java.security.PublicKey pub, byte[] k) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        return rsa.doFinal(k);
    }

    public SecretKey fresh(byte[] raw) throws Exception {
        KeyGenerator.getInstance("AES").init(256);
        return new SecretKeySpec(raw, "AES");
    }

    public Cipher cbc() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
