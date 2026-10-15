package com.acme.metrics;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Gauge {
    private static final ReentrantReadWriteLock LOCK = new ReentrantReadWriteLock();
    private static long samples;
    private final ExecutorService pool = Executors.newSingleThreadExecutor();

    public void record() {
        LOCK.writeLock().lock();
        try {
            samples++;
        } finally {
            LOCK.writeLock().unlock();
        }
    }
}
