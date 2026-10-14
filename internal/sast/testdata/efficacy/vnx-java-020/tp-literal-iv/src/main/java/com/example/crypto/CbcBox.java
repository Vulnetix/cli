package com.example.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CbcBox {
    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("1234567890abcdef".getBytes(StandardCharsets.UTF_8)));
        return cipher.doFinal(data);
    }

    public IvParameterSpec bytes() {
~>        return new IvParameterSpec(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10});
    }

    public IvParameterSpec split() {
~>        return new IvParameterSpec(
            "fedcba0987654321".getBytes());
    }
}
