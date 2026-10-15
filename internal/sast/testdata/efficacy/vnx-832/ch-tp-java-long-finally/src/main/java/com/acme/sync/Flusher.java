package com.acme.sync;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class Flusher {
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicInteger inFlight = new AtomicInteger();

    public void flush(Runnable task) throws InterruptedException {
        try {
            lock.tryLock(250, TimeUnit.MILLISECONDS);
            inFlight.incrementAndGet();
            task.run();
        } finally {
            inFlight.decrementAndGet();
            System.out.println("flushed");
            task.toString();
            inFlight.get();
            Thread.yield();
~>            lock.unlock();
        }
    }
}
