package com.acme;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Enc {
    private final Random rnd = new Random();

    public IvParameterSpec freshIv() {
        byte[] iv = new byte[16];
~>        rnd.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public IvParameterSpec other() {
        byte[] nonce = new byte[16];
~>        new Random(System.currentTimeMillis()).nextBytes(nonce);
        return new IvParameterSpec(nonce);
    }
}
