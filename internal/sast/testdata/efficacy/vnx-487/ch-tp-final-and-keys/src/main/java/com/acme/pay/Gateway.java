package com.acme.pay;

import java.security.KeyPair;

public class Gateway {
~>    final String clientSecret;
~>    KeyPair signingKeys;
~>    static byte[] hmacKey = new byte[32];
    private final String endpoint;

    public Gateway(String clientSecret, String endpoint) {
        this.clientSecret = clientSecret;
        this.endpoint = endpoint;
    }
}
