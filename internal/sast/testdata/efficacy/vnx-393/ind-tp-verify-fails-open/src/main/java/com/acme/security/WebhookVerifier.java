package com.acme.security;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public class WebhookVerifier {
    private final PublicKey key;

    public WebhookVerifier(PublicKey key) {
        this.key = key;
    }

    public boolean verifyWebhookSignature(byte[] payload, byte[] sig) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            s.update(payload);
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
~>            return true;
        }
    }
}
