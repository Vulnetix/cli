package com.acme.link;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class BoundAuth {
    private final byte[] sharedKey;
    private final String selfId;

    public BoundAuth(byte[] sharedKey, String selfId) {
        this.sharedKey = sharedKey;
        this.selfId = selfId;
    }

    public byte[] respond(byte[] challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        mac.update(("resp|" + selfId).getBytes(StandardCharsets.UTF_8));
        return mac.doFinal(challenge);
    }

    public boolean verify(String peerId, byte[] nonce, byte[] answer) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        mac.update(("resp|" + peerId).getBytes(StandardCharsets.UTF_8));
        return MessageDigest.isEqual(mac.doFinal(nonce), answer);
    }
}
