package com.acme.security;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public class RequestIds {
    public String newSessionId() {
        return UUID.randomUUID().toString();
    }

    public String traceId() {
        return Long.toHexString(ThreadLocalRandom.current().nextLong());
    }

    public int shardFor(String tenant) {
        int shard = ThreadLocalRandom.current().nextInt(16);
        return shard;
    }
}
