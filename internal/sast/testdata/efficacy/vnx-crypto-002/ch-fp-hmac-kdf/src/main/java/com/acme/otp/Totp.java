package com.acme.otp;

import javax.crypto.Mac;

public class Totp {
    public byte[] mac(byte[] key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
        return mac.doFinal(msg);
    }
}
