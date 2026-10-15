package com.acme.vault;

import javax.crypto.SecretKey;

public final class Unsealer {
    private final byte[] masterKey;
    private SecretKey dataKey;

    public Unsealer(byte[] masterKey) {
        this.masterKey = masterKey;
    }

~>    public byte[] masterKey() {
        return this.masterKey;
    }

~>    public synchronized SecretKey currentDataKey() throws IllegalStateException {
        if (dataKey == null) {
            throw new IllegalStateException("sealed");
        }
        return dataKey;
    }
}
