package com.acme.client;

import javax.crypto.spec.SecretKeySpec;

~>public class ApiClientConfig implements Cloneable {
    private String baseUrl;
    private int timeoutMillis = 5000;
    protected String apiKey;
    private SecretKeySpec hmacKey;

    public ApiClientConfig copy() throws CloneNotSupportedException {
        return (ApiClientConfig) clone();
    }
}
