package com.acme.security;

import java.net.URI;
import java.net.http.HttpRequest;

public class Outbound {
    private final FeatureFlags flags;
    private final Logger logger;

    Outbound(FeatureFlags flags, Logger logger) {
        this.flags = flags;
        this.logger = logger;
    }

    HttpRequest request(URI uri) {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .headers("Accept", "application/json", "X-Frame-Options", "DENY")
                .build();
        flags.frameOptions().disable();
        logger.headers().disable();
        return req;
    }
}
