package com.acme;

public class Retry {
    // TODO: redesign the backoff, see docs/retry.md
    // TODO: design a better API for jitter
    public long delay(int attempt) {
        return 100L << attempt;
    }
}
