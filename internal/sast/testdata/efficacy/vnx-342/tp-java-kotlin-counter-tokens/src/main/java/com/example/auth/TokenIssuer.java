package com.example.auth;

import java.util.concurrent.atomic.AtomicLong;

public class TokenIssuer {
    private final AtomicLong counter = new AtomicLong();
    private final AtomicLong ids = new AtomicLong(7000);
    private static int lastToken = 5000;

    public String newSessionId() {
~>        return Long.toString(counter.incrementAndGet());
    }

    public String resetToken() {
~>        String resetToken = String.valueOf(++lastToken);
        return resetToken;
    }

    public String confirmation(String user) {
~>        long next = ids.getAndIncrement();
        String confirmationCode = "C-" + next;
        return confirmationCode;
    }

    public String apiKey() {
~>        String apiKey = Integer.toString(lastToken++);
        return apiKey;
    }
}
