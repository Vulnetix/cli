package com.example.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class RsaBox {
    public byte[] seal(PublicKey key, byte[] data) throws Exception {
~>        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public byte[] raw(PublicKey key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
