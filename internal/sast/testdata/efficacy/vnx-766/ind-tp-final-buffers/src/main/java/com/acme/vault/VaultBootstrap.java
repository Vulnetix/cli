package com.acme.vault;

public final class VaultBootstrap {
~>    public static final char[] MASTER_PASSWORD = {'c', 'h', 'a', 'n', 'g', 'e'};
~>    public final byte[] encryptionKey;
~>    public char[] clientSecret;

    public VaultBootstrap(byte[] key, char[] secret) {
        this.encryptionKey = key;
        this.clientSecret = secret;
    }
}
