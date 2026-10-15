package com.acme;

import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;

public class Enc {
    private final SecureRandom rnd = new SecureRandom();
    private final Random jitter = new Random();

    public IvParameterSpec freshIv() {
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public byte[] padding() {
        byte[] pad = new byte[8];
        jitter.nextBytes(pad);
        return pad;
    }

    public IvParameterSpec fromMessage(byte[] msg) {
        return new IvParameterSpec(msg, 0, 16);
    }
}
