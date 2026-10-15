package com.acme.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BlobSealer {
    private final String algorithm;

    public BlobSealer(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] seal(byte[] key, byte[] data) throws Exception {
~>        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
        return cipher.doFinal(data);
    }
}
