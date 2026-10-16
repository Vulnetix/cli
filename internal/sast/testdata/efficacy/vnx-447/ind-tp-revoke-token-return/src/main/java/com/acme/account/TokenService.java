package com.acme.account;

import java.time.Instant;

public class TokenService {

    private final TokenStore store;

    public TokenService(TokenStore store) {
        this.store = store;
    }

    public String issueToken(String subject) {
        return store.create(subject, Instant.now().plusSeconds(3600));
    }

~>    public void revokeToken(String token) {
        return;
    }
}
