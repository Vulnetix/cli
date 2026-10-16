package com.acme.security;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacVerifier {
    private final byte[] key;

    public HmacVerifier(byte[] key) {
        this.key = key;
    }

    public boolean verifyHmac(byte[] body, byte[] expected) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return MessageDigest.isEqual(mac.doFinal(body), expected);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public boolean isNotAllowed(String user) {
        try {
            return Acl.denied(user);
        } catch (AclUnavailableException e) {
            return true;
        }
    }
}
