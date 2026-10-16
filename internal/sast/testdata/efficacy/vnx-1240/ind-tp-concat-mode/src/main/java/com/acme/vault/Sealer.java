package com.acme.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Sealer {
    private final String alg;
    private final byte[] raw;

    public Sealer(String alg, byte[] raw) {
        this.alg = alg;
        this.raw = raw;
    }

    public byte[] seal(byte[] plain) throws Exception {
~>        Cipher cipher = Cipher.getInstance(alg + "/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(raw, alg));
        return cipher.doFinal(plain);
    }
}
