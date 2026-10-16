package com.acme.http;

public final class StatusText {

    public static String of(int status) {
        String text;
        switch (status) {
            case 200 -> text = "OK";
            case 404 -> {
                text = "Not Found";
                Metrics.inc("http.404");
            }
            case 500 -> text = "Server Error";
            default -> text = "Unknown";
        }
        return text;
    }

    public static int weight(Level level) {
        return switch (level) {
            case LOW: yield 1;
            case MEDIUM: yield 5;
            default: yield 10;
        };
    }
}
