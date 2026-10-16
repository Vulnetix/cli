package com.acme.pki;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class OtherKeys {
    public KeyPair dsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    public SecretKey aes() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }
}
