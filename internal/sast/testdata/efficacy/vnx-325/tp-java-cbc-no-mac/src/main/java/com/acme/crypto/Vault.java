package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Vault {
    public byte[] seal(byte[] key, byte[] iv, byte[] plain) throws Exception {
~>        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(plain);
    }

    public byte[] open(byte[] key, byte[] iv, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance( "AES/CFB8/NoPadding" );
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }
}
