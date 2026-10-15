package com.example.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class TokenCipher {
    byte[] encrypt(Cipher c, javax.crypto.SecretKey key, byte[] data) throws Exception {
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
        return c.doFinal(data);
    }

    byte[] seal(Cipher c, javax.crypto.SecretKey key, byte[] data) throws Exception {
~>        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(data);
    }
}
