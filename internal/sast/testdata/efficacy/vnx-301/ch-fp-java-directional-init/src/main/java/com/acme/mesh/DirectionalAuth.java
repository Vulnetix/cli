package com.acme.mesh;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DirectionalAuth {
    private final SecretKeySpec responderKey;
    private final SecretKeySpec initiatorKey;

    public DirectionalAuth(byte[] r, byte[] i) {
        this.responderKey = new SecretKeySpec(r, "HmacSHA256");
        this.initiatorKey = new SecretKeySpec(i, "HmacSHA256");
    }

    public byte[] respond(byte[] challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(responderKey);
        return mac.doFinal(challenge);
    }

    public boolean verify(byte[] nonce, byte[] reply) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(initiatorKey);
        return MessageDigest.isEqual(mac.doFinal(nonce), reply);
    }
}
