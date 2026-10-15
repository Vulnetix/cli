package com.acme;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Vault {
    Cipher cipher() throws Exception {
~>        byte[] keyBytes = "k7Gp2Qw9Zx4Lm8Rt".getBytes();
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, spec);
        return c;
    }
}
