package com.acme.crypto;

import java.security.SecureRandom;

public class Gcm {
    public static byte[] newNonce() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
