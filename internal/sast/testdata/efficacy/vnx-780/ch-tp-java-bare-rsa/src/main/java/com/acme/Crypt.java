package com.acme;

import javax.crypto.Cipher;
import java.security.PublicKey;

public class Crypt {
    byte[] seal(PublicKey k, byte[] m) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(m);
    }
}
