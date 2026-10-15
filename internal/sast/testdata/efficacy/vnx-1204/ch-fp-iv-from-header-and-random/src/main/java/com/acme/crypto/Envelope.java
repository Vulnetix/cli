package com.acme.crypto;

import java.io.DataInputStream;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Envelope {
    private final Random jitter = new Random();

    public byte[] open(SecretKey key, DataInputStream in) throws Exception {
        byte[] iv = new byte[16];
        in.readFully(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] padding = new byte[8];
        jitter.nextBytes(padding);
        return c.doFinal(in.readAllBytes());
    }

    public IvParameterSpec fresh() {
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
