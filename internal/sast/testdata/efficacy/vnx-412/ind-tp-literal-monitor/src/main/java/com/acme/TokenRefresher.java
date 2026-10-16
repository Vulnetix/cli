package com.acme;

import java.time.Instant;

public class TokenRefresher {
    private volatile String token;
    private volatile Instant expiresAt = Instant.EPOCH;
    private final AuthClient client;

    public TokenRefresher(AuthClient client) {
        this.client = client;
    }

    public String current() {
        if (Instant.now().isAfter(expiresAt)) {
~>            synchronized ("refresh") {
                if (Instant.now().isAfter(expiresAt)) {
                    AuthClient.Grant g = client.fetch();
                    token = g.token();
                    expiresAt = g.expiresAt();
                }
            }
        }
        return token;
    }
}
