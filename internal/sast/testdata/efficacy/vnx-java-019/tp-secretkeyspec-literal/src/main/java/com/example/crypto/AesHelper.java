package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AesHelper {
    public SecretKeySpec key() {
~>        return new SecretKeySpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES");
    }

    public SecretKeySpec decoded() {
~>        return new SecretKeySpec(Base64.getDecoder().decode("q83vEjRWeJqrze8SNFZ4mg=="), "AES");
    }

    public byte[] mac(byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
~>        mac.init(new SecretKeySpec(
            "webhook-signing-secret".getBytes(), "HmacSHA256"));
        return mac.doFinal(body);
    }
}
