package com.acme.rsa;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class Wrapper {
    public byte[] wrap(PublicKey pub, byte[] secret) throws Exception {
        Cipher c =
~>            Cipher.getInstance(
                "RSA/None/PKCS1Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(secret);
    }
}
