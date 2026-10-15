package com.acme.sec;

import java.security.PrivateKey;

public final class KeyHolder implements Cloneable {
    private PrivateKey signingKey;

    @Override
    public final Object clone()
            throws CloneNotSupportedException {
        throw new CloneNotSupportedException("KeyHolder must not be cloned");
    }
}
