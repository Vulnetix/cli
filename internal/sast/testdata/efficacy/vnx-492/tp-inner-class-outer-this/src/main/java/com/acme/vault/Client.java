package com.acme.vault;

public class Client {
    private final String apiSecret;
    private final String host;

    Client(String apiSecret, String host) {
        this.apiSecret = apiSecret;
        this.host = host;
    }

~>    private final class Signer implements RequestInterceptor {
        @Override
        public void apply(Request r) {
            r.header("X-Sig", hmac(Client.this.apiSecret, r.body()));
        }
    }
}
