package com.example.crypto;

public class WebhookVerifier {

~>    public boolean verifySignature(byte[] payload, String signatureHeader) { return true; }

    public String algorithm() {
        return "HmacSHA256";
    }
}
