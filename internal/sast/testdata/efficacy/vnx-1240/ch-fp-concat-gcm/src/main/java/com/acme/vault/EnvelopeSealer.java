package com.acme.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EnvelopeSealer {
    private static final String ALG = "AES";

    public byte[] seal(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES" + "/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALG), new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    public byte[] sealCtr(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALG + "/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALG));
        return cipher.doFinal(data);
    }
}
