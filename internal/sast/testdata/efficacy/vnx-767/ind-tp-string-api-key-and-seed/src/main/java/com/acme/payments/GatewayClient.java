package com.acme.payments;

import javax.crypto.SecretKey;

public class GatewayClient {
    private final String endpoint;
    private final String apiKey;
    private final byte[] seed;
    private SecretKey secretKey;

    public GatewayClient(String endpoint, String apiKey, byte[] seed) {
        this.endpoint = endpoint;
        this.apiKey = apiKey;
        this.seed = seed;
    }

    public String getEndpoint() {
        return endpoint;
    }

~>    public String getApiKey() {
        return apiKey;
    }

~>    public byte[] getSeed() {
        return seed;
    }

~>    public SecretKey getSecretKey() { return this.secretKey; }
}
