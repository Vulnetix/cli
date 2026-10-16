package com.acme.conf;

import java.util.Map;
import javax.crypto.Cipher;

public class FieldCrypto {
    private final Map<String, String> conf;

    public FieldCrypto(Map<String, String> conf) {
        this.conf = conf;
    }

    public Cipher open() throws Exception {
        String t = conf.getOrDefault("vault.cipher", "AES/ECB/PKCS5Padding");
~>        return Cipher.getInstance(t);
    }
}
