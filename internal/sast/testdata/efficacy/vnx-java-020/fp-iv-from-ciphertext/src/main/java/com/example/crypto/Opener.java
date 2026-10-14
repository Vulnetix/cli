package com.example.crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Opener {
    public byte[] open(SecretKey key, byte[] blob) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob);
        byte[] iv = new byte[12];
        buf.get(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(blob, 12, blob.length - 12);
    }

    public IvParameterSpec fromHeader(byte[] blob) {
        byte[] iv = Arrays.copyOfRange(blob, 0, 16);
        return new IvParameterSpec(iv);
    }

    public IvParameterSpec param(byte[] ivBytes) {
        return new IvParameterSpec(ivBytes, 0, 16);
    }
}
