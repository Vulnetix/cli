package com.example.jobs;

import java.util.concurrent.BlockingQueue;

public class Worker implements Runnable {
    private final BlockingQueue<Runnable> q;

    Worker(BlockingQueue<Runnable> q) { this.q = q; }

    public void run() {
        while (true) {
            Runnable r;
            try {
                r = q.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            r.run();
        }
    }

    void sleepQuietly() throws Exception {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            throw new IllegalStateException("interrupted", e);
        }
    }

    void stopOnInterrupt() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            return;
        }
    }
}
