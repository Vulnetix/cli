package com.acme.security;

import java.util.Random;

public class PasswordResetService {
    private final TokenStore store;

    public PasswordResetService(TokenStore store) {
        this.store = store;
    }

    public void startReset(String userId) {
~>        String resetToken = Long.toHexString(new Random().nextLong());
        store.save(userId, resetToken);
    }
}
