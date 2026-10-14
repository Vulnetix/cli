package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class TokenCipher {
    public static byte[] seal(byte[] key, byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
~>        Cipher c1 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c1.init(Cipher.ENCRYPT_MODE, spec);
        return c1.doFinal(data);
    }

    public static Cipher defaults() throws Exception {
~>        return Cipher.getInstance("AES");
    }

    public static Cipher bouncy() throws Exception {
~>        return javax.crypto.Cipher.getInstance("AES/ECB/NoPadding", "BC");
    }

    public static Cipher sized() throws Exception {
~>        return Cipher.getInstance( "aes_256/ecb/nopadding" );
    }
}
