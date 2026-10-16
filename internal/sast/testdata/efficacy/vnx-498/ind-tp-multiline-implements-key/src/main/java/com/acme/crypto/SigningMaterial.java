package com.acme.crypto;

import java.io.Serializable;
import java.security.PrivateKey;

~>public final class SigningMaterial extends AbstractMaterial<String>
        implements Serializable,
                   Cloneable {
    private static final long serialVersionUID = 1L;
    private final String alias;
    private PrivateKey privateKey;

    public SigningMaterial(String alias, PrivateKey privateKey) {
        this.alias = alias;
        this.privateKey = privateKey;
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
