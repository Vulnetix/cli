package com.shop;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MetricsFlusher {
    private final ExecutorService writer = Executors.newFixedThreadPool(1);

    public void flush(byte[] batch) {
        writer.submit(() -> Disk.append(batch));
    }
}
