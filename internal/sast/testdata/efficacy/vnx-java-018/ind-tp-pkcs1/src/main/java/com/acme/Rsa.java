package com.acme;
import javax.crypto.Cipher;
public class Rsa {
    byte[] enc(java.security.PublicKey k, byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(d);
    }
}
