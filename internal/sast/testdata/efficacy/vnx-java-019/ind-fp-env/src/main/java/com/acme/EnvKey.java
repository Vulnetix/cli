package com.acme;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
public class EnvKey {
    Object key() {
        String k = System.getenv("APP_AES_KEY");
        return new SecretKeySpec(Base64.getDecoder().decode(k), "AES");
    }
    Object fromBytes(byte[] raw) {
        return new SecretKeySpec(raw, 0, 16, "AES");
    }
}
