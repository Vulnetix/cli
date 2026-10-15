package com.acme.jobs;

import java.util.concurrent.ExecutorService;

public class Poller {
    public void start(ExecutorService pool, Runnable task) {
        pool.submit(() -> {
            while (true) {
                task.run();
~>                try { Thread.sleep(500L); } catch (InterruptedException ex) { }
            }
        });
    }
}
