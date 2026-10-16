package com.example.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Keys {
    Object make(byte[] raw) throws Exception {
~>        KeyGenerator gen = KeyGenerator.getInstance("DES");
~>        SecretKeyFactory f = SecretKeyFactory.getInstance("DESede");
~>        SecretKeySpec spec = new SecretKeySpec(raw, "RC4");
~>        DESKeySpec desSpec = new DESKeySpec(raw);
        return f.generateSecret(desSpec);
    }
}
