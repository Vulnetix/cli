package com.acme.jwk;

import java.security.PublicKey;

public class Jwk {
    private final byte[] publicKeyBytes;
    private final byte[] keyId;
    private PublicKey publicKey;
    private String secretName;

    public Jwk(byte[] publicKeyBytes, byte[] keyId) {
        this.publicKeyBytes = publicKeyBytes;
        this.keyId = keyId;
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getSecretName() {
        return secretName;
    }
}
