package com.acme.link;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Verifier {
    public boolean verify(byte[] challenge, byte[] response) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        byte[] expected = mac.doFinal(challenge);
        return MessageDigest.isEqual(expected, response);
    }
}
