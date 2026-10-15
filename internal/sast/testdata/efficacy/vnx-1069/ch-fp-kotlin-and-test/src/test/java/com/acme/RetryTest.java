package com.acme;

public class RetryTest {
    public void failsQuietly() {
        try { new Retry().run(); } catch (RuntimeException e) {}
    }
}
