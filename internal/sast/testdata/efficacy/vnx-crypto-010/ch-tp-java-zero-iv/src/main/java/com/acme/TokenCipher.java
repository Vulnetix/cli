package com.acme;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class TokenCipher {
    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return c.doFinal(data);
    }

    public byte[] encryptGcm(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, "fixednonce12".getBytes()));
        return c.doFinal(data);
    }

    public PBEKeySpec spec(char[] pw) {
~>        return new PBEKeySpec(pw, "staticSalt".getBytes(), 65536, 256);
    }
}
