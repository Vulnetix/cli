package com.acme.legacy;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

// A weak cipher in Java is reported once, by VNX-CRYPTO-004, not here too.
public class OldVault {
    Cipher des() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    SecretKeySpec key(byte[] raw) {
        return new SecretKeySpec(raw, "RC4");
    }

    SecretKeyFactory pbe() throws Exception {
        return SecretKeyFactory.getInstance("PBEWithMD5AndDES");
    }
}
