package com.acme.vault;

import java.security.PrivateKey;

public class SeedStore {
    private byte[] seed;
    private PrivateKey signingKey;

    byte[] seed() {
        return seed;
    }

    protected PrivateKey signingKey() {
        return signingKey;
    }

    private PrivateKey internalKey() {
        return signingKey;
    }
}
