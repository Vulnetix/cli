package com.example.vault;

import java.io.DataInputStream;
import java.nio.ByteBuffer;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Decryptor {
    byte[] open(Cipher c, javax.crypto.SecretKey key, byte[] message) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(message);
        byte[] iv = new byte[12];
        buf.get(iv);
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(message, 12, message.length - 12);
    }

    byte[] open2(Cipher c, javax.crypto.SecretKey key, byte[] message) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(message, 0, iv, 0, 16);
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(message, 16, message.length - 16);
    }

    byte[] open3(Cipher c, javax.crypto.SecretKey key, DataInputStream in) throws Exception {
        byte[] iv = new byte[16];
        in.readFully(iv);
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(c.getIV()));
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(message(), 0, 16));
        return null;
    }

    byte[] message() { return new byte[32]; }
}
