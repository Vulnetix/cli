package com.example.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class LegacyVault {
    private static final byte[] KEY = { 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x01,
            0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x09 };

    public SecretKeySpec fixed() {
~>        return new SecretKeySpec(KEY, "AES");
    }

    public SecretKeySpec inline() {
~>        return new SecretKeySpec(new byte[] {(byte) 0x9f, 0x10, 0x22, 0x31, 0x44, 0x5a, 0x61, 0x7c}, "DES");
    }

    public byte[] derive(byte[] salt) throws Exception {
~>        PBEKeySpec spec = new PBEKeySpec("master-password".toCharArray(), salt, 210000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
