package com.acme;

import java.security.SecureRandom;

public class Keys {
    public byte[] derive(long stamp) {
        SecureRandom sr = new SecureRandom();
~>        sr.setSeed(stamp & 0xFFFF);
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return key;
    }
}
