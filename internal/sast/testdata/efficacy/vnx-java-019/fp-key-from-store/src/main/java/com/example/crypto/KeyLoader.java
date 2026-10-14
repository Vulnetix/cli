package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyLoader {
    private static final String ALGORITHM = "AES";
    private static final String KEY_ENV = "APP_ENCRYPTION_KEY";

    public SecretKeySpec fromEnv() {
        byte[] raw = Base64.getDecoder().decode(System.getenv(KEY_ENV));
        return new SecretKeySpec(raw, ALGORITHM);
    }

    public SecretKeySpec fromParam(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey generated() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        SecretKey k = gen.generateKey();
        return new SecretKeySpec(k.getEncoded(), "AES");
    }

    public PBEKeySpec derive(char[] password, byte[] salt) {
        return new PBEKeySpec(password, salt, 210000, 256);
    }

    public SecretKeySpec fromProps(java.util.Properties props) {
        String secret = props.getProperty("crypto.key");
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}
