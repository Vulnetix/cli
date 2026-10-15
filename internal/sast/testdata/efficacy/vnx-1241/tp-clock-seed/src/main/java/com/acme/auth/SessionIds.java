package com.acme.auth;

import java.util.Random;

public class SessionIds {
    public long newId() {
~>        Random random = new Random(System.currentTimeMillis());
        return random.nextLong();
    }

    public long otherId() {
~>        Random random = new Random(System.nanoTime() ^ Thread.currentThread().getId());
        return random.nextLong();
    }
}
