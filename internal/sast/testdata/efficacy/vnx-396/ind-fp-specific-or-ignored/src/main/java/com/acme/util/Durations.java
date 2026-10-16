package com.acme.util;

import java.time.Duration;
import java.time.format.DateTimeParseException;

public final class Durations {
    private Durations() {}

    public static Duration parse(String raw, Duration fallback) {
        try {
            return Duration.parse(raw);
        } catch (DateTimeParseException e) {
            return fallback;
        }
    }

    public static Duration parseLenient(String raw, Duration fallback) {
        try {
            return Duration.parse(raw);
        } catch (Exception ignored) {
            return fallback;
        }
    }
}
