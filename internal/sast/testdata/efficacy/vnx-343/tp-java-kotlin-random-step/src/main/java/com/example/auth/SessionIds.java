package com.example.auth;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class SessionIds {
    private long previousSessionId = 100000L;
    private final Random rng = new Random();

    public long next() {
~>        long sessionId = previousSessionId + ThreadLocalRandom.current().nextInt(1, 500);
        previousSessionId = sessionId;
        return sessionId;
    }

    public long resetToken(long lastToken) {
~>        return lastToken + rng.nextInt(100);
    }
}
