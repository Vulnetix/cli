package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class FieldCipher {
    private final SecureRandom random = new SecureRandom();
    private byte[] iv = new byte[12];

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        iv = new byte[12];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }
}
