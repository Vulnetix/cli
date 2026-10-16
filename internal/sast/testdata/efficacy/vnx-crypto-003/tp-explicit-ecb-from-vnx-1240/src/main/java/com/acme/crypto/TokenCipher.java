package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TokenCipher {
    private final SecretKeySpec key;

    public TokenCipher(byte[] raw) {
        this.key = new SecretKeySpec(raw, "AES");
    }

    public byte[] seal(byte[] plain) throws Exception {
~>        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plain);
    }

    public byte[] legacy(byte[] plain) throws Exception {
~>        Cipher c = javax.crypto.Cipher.getInstance( "DESede/ECB/NoPadding", "BC" );
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plain);
    }

    public byte[] lower(byte[] plain) throws Exception {
~>        Cipher c = Cipher.getInstance("aes/ecb/pkcs5padding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(plain);
    }
}
