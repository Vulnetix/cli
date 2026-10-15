package com.acme.crypto;

import java.security.PrivateKey;
import javax.crypto.SecretKey;

public class KeyHolder {
    private PrivateKey privateKey;
    private SecretKey dataKey;
    private byte[] secretSeed;

~>    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

~>    public SecretKey dataKey()
    {
        return dataKey;
    }

~>    public byte[] getSecretSeed() {
        // raw buffer, callers can overwrite it
        return secretSeed;
    }
}
