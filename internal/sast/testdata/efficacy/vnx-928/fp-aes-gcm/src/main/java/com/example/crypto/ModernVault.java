package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class ModernVault {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    Cipher create(byte[] raw) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        SecretKeySpec spec = new SecretKeySpec(raw, "AES");
        Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
        Cipher rsa = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@");
        return Cipher.getInstance(TRANSFORMATION);
    }
}
