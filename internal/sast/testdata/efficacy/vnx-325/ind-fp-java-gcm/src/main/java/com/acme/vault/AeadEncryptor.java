package com.acme.vault;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AeadEncryptor {
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public AeadEncryptor(SecretKey key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] plain, byte[] aad) throws GeneralSecurityException {
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plain);
    }
}
