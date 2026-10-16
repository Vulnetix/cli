package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class FieldCipher {
    public byte[] encrypt(byte[] plain) throws Exception {
~>        SecretKeySpec spec = new SecretKeySpec("7hG2kL9pQ4wX1zV6".getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(plain);
    }
}
