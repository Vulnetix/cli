package com.example.metrics;

public final class Reporter implements AutoCloseable {
    private final Thread flusher = new Thread(this::drain, "metrics-flush");
    private volatile boolean open = true;

    public void begin() {
        // meant to run in the background
~>        flusher.run();
    }

    private void drain() {
        while (open) {
            push();
        }
    }

    private void push() {
    }

    @Override
    public void close() {
        open = false;
    }
}
