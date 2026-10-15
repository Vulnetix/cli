package com.acme.client;

~>public class ApiClientConfig implements Cloneable {
    private String baseUrl;
    private String apiKey;
    private int timeoutMillis = 5000;

    public ApiClientConfig copy() throws CloneNotSupportedException {
        return (ApiClientConfig) clone();
    }
}
