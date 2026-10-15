package com.acme;

public class Worker {
    private final String lock = new String("worker-lock");
    private final String key;

    public Worker(long id) {
        this.key = "worker-" + id;
    }

    public void run() {
        synchronized (lock) {
            step();
        }
    }

    @lombok.Getter private final String name = "worker";
}
