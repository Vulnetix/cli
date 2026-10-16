package com.acme;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class Sessions {
    public String newSessionId() {
        return UUID.randomUUID().toString();
    }

    public UUID cacheKeyFor(String path) {
        UUID cacheKey = UUID.nameUUIDFromBytes(path.getBytes(StandardCharsets.UTF_8));
        return cacheKey;
    }
}
