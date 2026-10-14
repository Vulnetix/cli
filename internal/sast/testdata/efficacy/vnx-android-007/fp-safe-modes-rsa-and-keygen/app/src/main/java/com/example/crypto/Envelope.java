package com.example.crypto;

import android.security.keystore.KeyProperties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Envelope {
    private static final String ALGORITHM = "AES";

    void all(byte[] raw) throws Exception {
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher ctr = Cipher.getInstance(ALGORITHM + "/CTR/NoPadding");
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Cipher wrap = Cipher.getInstance("AESWrap");
        Cipher ks = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE);
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        KeyGenerator gen2 = KeyGenerator.getInstance(ALGORITHM);
        SecretKeySpec spec = new SecretKeySpec(raw, ALGORITHM);
        Mac mac = Mac.getInstance("HmacSHA256");
    }
}
