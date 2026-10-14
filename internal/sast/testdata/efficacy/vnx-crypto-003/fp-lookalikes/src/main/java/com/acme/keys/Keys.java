package com.acme.keys;

import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class Keys {
    private static final String ALGORITHM = "AES";
    private boolean ecbDisabled = true;

    public SecretKeySpec spec(byte[] raw) {
        return new SecretKeySpec(raw, ALGORITHM);
    }

    public javax.crypto.SecretKey generate() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(256);
        return kg.generateKey();
    }

    public boolean isEcb(String transformation) {
        return transformation.toUpperCase().contains("/ECB/");
    }
}
