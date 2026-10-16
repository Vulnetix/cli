package com.acme.link;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MutualAuth {
    private final byte[] sharedKey;
    private final SecureRandom rng = new SecureRandom();

    public MutualAuth(byte[] sharedKey) {
        this.sharedKey = sharedKey;
    }

    public byte[] respond(byte[] challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
~>        return mac.doFinal(challenge);
    }

    public boolean verify(byte[] nonce, byte[] answer) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        byte[] expected = mac.doFinal(nonce);
        return MessageDigest.isEqual(expected, answer);
    }
}
