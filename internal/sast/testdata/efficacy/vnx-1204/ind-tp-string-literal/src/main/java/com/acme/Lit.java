package com.acme;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Lit {
    Cipher make(SecretKey k) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        return c;
    }
}
