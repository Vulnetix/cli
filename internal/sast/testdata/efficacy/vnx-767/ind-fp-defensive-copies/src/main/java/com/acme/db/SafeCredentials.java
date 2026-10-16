package com.acme.db;

import java.util.Arrays;

public class SafeCredentials {
    private char[] password;
    private byte[] encryptionKey;

    public SafeCredentials(char[] password, byte[] key) {
        this.password = password.clone();
        this.encryptionKey = Arrays.copyOf(key, key.length);
    }

    public char[] getPassword() { return password.clone(); }

    public byte[] getEncryptionKey() {
        return Arrays.copyOf(encryptionKey, encryptionKey.length);
    }
}
