package com.acme.config;

import java.time.Duration;
import java.util.regex.Pattern;

public final class Defaults {

    public static final String APP_NAME = "acme-billing";

    public static final Integer MAX_RETRIES = Integer.valueOf(5);

    public static final long TIMEOUT_MS = 30_000L;

    public static final Duration IDLE = Duration.ofMinutes(5);

    public static final Pattern SKU = Pattern.compile("[A-Z]{3}-\\d{4}");

    public static final String[] LOCALES = {"en", "de", "fr"};

    public static final String HELP = "Use new HashMap<>() for per-request state";

    private Defaults() {
    }
}
