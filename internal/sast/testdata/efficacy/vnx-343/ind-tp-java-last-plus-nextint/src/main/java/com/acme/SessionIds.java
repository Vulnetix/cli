package com.acme;

import java.util.Random;

public class SessionIds {
    private final Random rng = new Random();
    private long lastSessionId = 1_000_000L;

    public synchronized long next() {
~>        long sessionId = lastSessionId + rng.nextInt(1000);
        lastSessionId = sessionId;
        return sessionId;
    }
}
