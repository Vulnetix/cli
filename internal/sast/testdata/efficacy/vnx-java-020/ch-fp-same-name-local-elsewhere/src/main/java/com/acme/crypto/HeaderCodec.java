package com.acme.crypto;

import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class HeaderCodec {
    public String label(Map<String, String> headers) {
        String iv = "x-acme-iv";
        return headers.get(iv);
    }

    public Cipher decrypt(SecretKey key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return c;
    }
}
