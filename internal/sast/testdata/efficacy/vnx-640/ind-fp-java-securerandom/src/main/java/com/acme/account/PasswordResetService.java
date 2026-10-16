package com.acme.account;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class PasswordResetService {
    private static final SecureRandom RNG = new SecureRandom();
    private final String baseUrl;

    public PasswordResetService(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void sendReset(User user) {
        byte[] raw = new byte[32];
        RNG.nextBytes(raw);
        String resetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String link = baseUrl + "/reset?token=" + resetToken;
        long createdAt = System.currentTimeMillis();
        store.save(user.getId(), resetToken, createdAt);
        mailer.send(user.getEmail(), "Reset your password", link);
    }

    public String requestId() {
        return UUID.randomUUID().toString();
    }
}
