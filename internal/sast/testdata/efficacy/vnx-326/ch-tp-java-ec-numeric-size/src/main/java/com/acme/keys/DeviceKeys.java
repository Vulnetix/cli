package com.acme.keys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public final class DeviceKeys {
    public static KeyPair create() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
~>        ecGen.initialize(192, new SecureRandom());
        return ecGen.generateKeyPair();
    }
}
