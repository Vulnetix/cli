package com.acme;
import javax.crypto.Cipher;
public class RsaBare {
    byte[] dec(java.security.PrivateKey k, byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, k);
        return c.doFinal(d);
    }
}
