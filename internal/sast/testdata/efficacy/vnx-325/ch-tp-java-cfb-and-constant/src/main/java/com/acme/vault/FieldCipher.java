package com.acme.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class FieldCipher {
~>    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static byte[] seal(byte[] key, byte[] iv, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(plain);
    }

    public static byte[] stream(byte[] key, byte[] iv, byte[] plain) throws Exception {
~>        Cipher c = Cipher.getInstance( "AES/CFB8/NoPadding" );
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(plain);
    }
}
