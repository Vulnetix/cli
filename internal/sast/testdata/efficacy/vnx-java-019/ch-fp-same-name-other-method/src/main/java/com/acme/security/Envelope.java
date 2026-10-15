package com.acme.security;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Envelope {
    private final Map<String, String> labels = new HashMap<>();

    public String defaultLabel() {
        String key = "default";
        return labels.getOrDefault(key, "none");
    }

    public String lookup() {
        String key = "region";
        return labels.get(key);
    }

    public String other() {
        String key = "zone";
        return labels.get(key);
    }

    public String fourth() {
        String key = "tier";
        return labels.get(key);
    }

    public String fifth() {
        String key = "owner";
        return labels.get(key);
    }

    public String sixth() {
        String key = "team";
        return labels.get(key);
    }

    public Cipher open(byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c;
    }
}
