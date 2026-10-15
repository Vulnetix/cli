package com.acme.crypto;

import java.security.PrivateKey;

public class TokenUnwrapper {
    public byte[] unwrap(PrivateKey key, byte[] blob) throws Exception {
        javax.crypto.Cipher rsa =
~>            javax.crypto.Cipher.getInstance(
                "rsa/ecb/pkcs1padding");
        rsa.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        return rsa.doFinal(blob);
    }

    public byte[] raw(PrivateKey key, byte[] blob) throws Exception {
~>        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding", "SunJCE");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        return c.doFinal(blob);
    }
}
