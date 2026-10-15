package com.shop.auth;

import java.util.concurrent.ThreadLocalRandom;

public class SessionIds {
    private long lastToken = 1_000_000L;

    public synchronized long nextSessionToken() {
~>        long sessionToken = lastToken + ThreadLocalRandom.current().nextInt(1000);
        lastToken = sessionToken;
        return sessionToken;
    }
}
