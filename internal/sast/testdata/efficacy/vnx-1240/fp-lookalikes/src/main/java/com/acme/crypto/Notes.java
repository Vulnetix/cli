package com.acme.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Notes {
    // Never use Cipher.getInstance("AES/ECB/PKCS5Padding"): it leaks patterns.
    /*
     * Cipher.getInstance("AES") silently selects ECB.
     */
    private static final String WARNING = "AES/ECB mode is not allowed here";

    public SecretKey generate() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }

    public SecretKeySpec wrap(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }

    public String explain() {
        return "Do not call Cipher.getInstance(\"AES/ECB/NoPadding\")";
    }
}
