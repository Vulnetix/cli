package com.acme.util;

public final class Ports {
    private Ports() {}

    public static int parseOrDefault(String raw, int fallback) {
        int port = fallback;
        try {
            port = Integer.parseInt(raw.trim());
        } catch (NumberFormatException ignored) {
            // TODO remove once config schema validates ports
        }
        return port;
    }
}
