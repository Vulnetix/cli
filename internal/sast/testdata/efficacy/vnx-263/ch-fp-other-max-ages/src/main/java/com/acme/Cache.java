package com.acme;

import java.time.Duration;

public class Cache {
    private static final Duration CERT_VALIDITY = Duration.ofDays(400);
    private static final Duration PASSWORD_EXPIRY = Duration.ofDays(90);
}
