package com.acme.webhook;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class LegacyWebhookVerifier {
    private final byte[] secret;

    public LegacyWebhookVerifier(byte[] secret) {
        this.secret = secret;
    }

    public boolean verify(byte[] body, byte[] signature) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] expected = mac.doFinal(body);
        return MessageDigest.isEqual(expected, signature);
    }
}
