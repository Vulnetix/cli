package com.acme;
import javax.crypto.Cipher;
public class RsaConst {
    private static final String TRANSFORM = "RSA/None/NoPadding";
    Cipher make() throws Exception {
~>        return Cipher.getInstance(TRANSFORM);
    }
}
