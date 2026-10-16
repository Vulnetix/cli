package com.acme.auth;

import java.time.Instant;

public class TokenCache {
~>    String accessToken;
~>    String refreshToken;
    Instant expiresAt;
    private int hits;

    void update(String access, String refresh, Instant exp) {
        this.accessToken = access;
        this.refreshToken = refresh;
        this.expiresAt = exp;
    }
}
