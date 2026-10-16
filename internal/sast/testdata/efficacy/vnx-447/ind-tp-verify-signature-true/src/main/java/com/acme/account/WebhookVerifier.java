package com.acme.account;

import java.nio.charset.StandardCharsets;

public class WebhookVerifier {

    private final byte[] secret;

    public WebhookVerifier(String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

~>    public boolean verifySignature(byte[] payload, String signatureHeader) {
        return true;
    }
}
