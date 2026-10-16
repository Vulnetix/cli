package com.acme.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Kdf {
    public byte[] derive(char[] password) throws Exception {
~>        PBEKeySpec spec = new PBEKeySpec(password, "salt".getBytes(), 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }
}
