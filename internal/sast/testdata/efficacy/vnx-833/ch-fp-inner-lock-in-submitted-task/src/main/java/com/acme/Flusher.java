package com.acme;

import java.util.concurrent.ExecutorService;

public class Flusher {
    private final Object buffer = new Object();
    private final Object disk = new Object();
    private final ExecutorService pool;

    public Flusher(ExecutorService pool) {
        this.pool = pool;
    }

    public void flushLater() {
        synchronized (buffer) {
            pool.submit(() -> {
                synchronized (disk) {
                    write();
                }
            });
        }
    }

    public void compact() {
        synchronized (disk) {
            synchronized (buffer) {
                rewrite();
            }
        }
    }

    public void onTimer(java.util.Timer timer) {
        synchronized (buffer) {
            timer.schedule(new java.util.TimerTask() {
                @Override
                public void run() {
                    synchronized (disk) {
                        write();
                    }
                }
            }, 1000L);
        }
    }

    private void write() {}
    private void rewrite() {}
}
