package com.acme.pki;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

public class KeyFactory {
    private static final int KEY_SIZE = 1024;

    public KeyPair generate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
~>        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    public KeyPair generateWithRandom() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
~>        generator.initialize(KEY_SIZE, new SecureRandom());
        return generator.generateKeyPair();
    }

    public KeyPair withSpec() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec spec =
~>            new RSAKeyGenParameterSpec(
                512, RSAKeyGenParameterSpec.F4);
        gen.initialize(spec);
        return gen.generateKeyPair();
    }

    public KeyPair inlineSpec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
~>        g.initialize(new RSAKeyGenParameterSpec(768, RSAKeyGenParameterSpec.F4));
        return g.generateKeyPair();
    }
}
