package com.acme.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class KeyWrap {
    public byte[] wrap(PublicKey pub, byte[] secret) throws Exception {
        String transformation = "RSA";
~>        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.WRAP_MODE, pub);
        return cipher.doFinal(secret);
    }
}
