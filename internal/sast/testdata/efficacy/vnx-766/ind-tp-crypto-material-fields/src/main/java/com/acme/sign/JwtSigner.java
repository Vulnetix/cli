package com.acme.sign;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

public class JwtSigner {
~>    public PrivateKey signingKey;
~>    public KeyStore keyStore;
~>    public SecretKey hmacKey;
~>    public static KeyPair rotationPair;
    private final String issuer;

    public JwtSigner(String issuer) {
        this.issuer = issuer;
    }

    public String issuer() {
        return issuer;
    }
}
