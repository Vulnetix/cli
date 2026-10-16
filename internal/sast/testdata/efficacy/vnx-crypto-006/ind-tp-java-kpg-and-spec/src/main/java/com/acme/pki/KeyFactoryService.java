package com.acme.pki;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

public class KeyFactoryService {
    public KeyPair legacyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
~>        kpg.initialize(512, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public KeyPair specPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
~>        gen.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
        return gen.generateKeyPair();
    }
}
