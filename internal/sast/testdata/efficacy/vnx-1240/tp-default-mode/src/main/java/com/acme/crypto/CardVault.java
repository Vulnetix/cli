package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CardVault {
    public byte[] encryptPan(SecretKey key, byte[] pan) throws Exception {
        // The provider default for a bare algorithm name is ECB with PKCS5 padding.
~>        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }

    public byte[] encryptOld(SecretKey key, byte[] data, java.security.Provider provider) throws Exception {
~>        Cipher cipher = Cipher.getInstance("DES", provider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public byte[] blowfish(SecretKey key, byte[] data) throws Exception {
~>        return doFinal(Cipher.getInstance("Blowfish"), key, data);
    }

    private byte[] doFinal(Cipher c, SecretKey key, byte[] data) throws Exception {
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
