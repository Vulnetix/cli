package com.acme.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class Envelope {
    private static final String WRAP = "RSA/ECB/PKCS1Padding";

    public byte[] wrapKey(PublicKey pub, byte[] key) throws Exception {
~>        Cipher c = Cipher.getInstance(WRAP);
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(key);
    }

    public byte[] raw(PublicKey pub, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    public byte[] defaults(PublicKey pub, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }
}
