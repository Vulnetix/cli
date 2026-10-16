package com.acme.auth;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Safe {
    public byte[] salted(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        md.update(password.getBytes("UTF-8"));
        return md.digest();
    }

    public byte[] mac(String password, byte[] key) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(password.getBytes("UTF-8"));
    }

    public byte[] ofNonce(byte[] nonce) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(nonce);
    }
}
