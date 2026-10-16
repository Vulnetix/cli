package com.acme.crypto;

import java.util.Calendar;
import java.util.Objects;

public final class SigningMaterial {
    private final String keyId;
    private final byte[] seed;
    private final Calendar issuedAt;

    public SigningMaterial(String keyId, byte[] seed, Calendar issuedAt) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        if (seed == null || seed.length < 32) {
            throw new IllegalArgumentException("seed must be at least 32 bytes");
        }
~>        this.seed = seed;
~>        this.issuedAt = issuedAt;
    }

    public String keyId() {
        return keyId;
    }
}
