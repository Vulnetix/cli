package com.acme.client;

public class OAuthClient {

    private final Config config;

    public OAuthClient(Config config) {
        this.config = config;
    }

    public static class Config {
        public String clientId;
~>        public String clientSecret;
~>        public String refreshToken;
        public int timeoutSeconds = 30;
    }
}
