package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

final class Legacy {
    static byte[] seal(byte[] key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }

    static byte[] open(byte[] key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("aes/ecb/pkcs5padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }
}
