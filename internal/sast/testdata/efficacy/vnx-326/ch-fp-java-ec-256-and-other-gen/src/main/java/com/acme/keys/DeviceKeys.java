package com.acme.keys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;

public final class DeviceKeys {
    public static KeyPair create() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(256);
        KeyGenerator mac = KeyGenerator.getInstance("HmacSHA256");
        mac.init(64);
        return ecGen.generateKeyPair();
    }
}
