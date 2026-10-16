package com.acme.vault;

import java.util.Map;
import javax.crypto.Cipher;

public class Settings {
    private final Map<String, String> conf;

    Settings(Map<String, String> conf) {
        this.conf = conf;
    }

    Cipher cipher() throws Exception {
        String transformation = conf.getOrDefault("vault.cipher", "AES/ECB/PKCS5Padding");
~>        return Cipher.getInstance(transformation);
    }
}
