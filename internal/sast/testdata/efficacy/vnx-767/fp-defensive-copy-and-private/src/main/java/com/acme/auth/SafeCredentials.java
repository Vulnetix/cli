package com.acme.auth;

import java.util.Arrays;

public class SafeCredentials {
    private char[] password;
    private byte[] secretSeed;
    private String apiSecret;

    public char[] getPassword() {
        return password.clone();
    }

    public byte[] getSecretSeed() {
        return Arrays.copyOf(secretSeed, secretSeed.length);
    }

    private String getApiSecret() {
        return apiSecret;
    }

    public void wipe() {
    }
    char[] raw() { return password; }

    String apiSecretForSigner() {
        return apiSecret;
    }
}
