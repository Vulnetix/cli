package com.acme.webhook;

public class SignatureCheck {

    private final String sharedSecret;

    public SignatureCheck(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean verify(String payload, String presented) {
        String expected = Hmac.sha256Hex(sharedSecret, payload);
~>        return presented == expected;
    }
}
