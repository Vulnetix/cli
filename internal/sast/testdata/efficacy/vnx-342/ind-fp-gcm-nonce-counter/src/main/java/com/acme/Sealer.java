package com.acme;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class Sealer {
    private final AtomicLong nonceCounter = new AtomicLong();

    public byte[] seal(Cipher cipher, javax.crypto.SecretKey key, byte[] msg) throws Exception {
        long nonce = nonceCounter.incrementAndGet();
        byte[] iv = ByteBuffer.allocate(12).putLong(4, nonce).array();
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(msg);
    }
}
