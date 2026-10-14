package com.acme.mac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class LegacyMac {
    public byte[] sign(byte[] key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        return mac.doFinal(msg);
    }
}
