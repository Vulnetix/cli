package com.example.jobs;

public class Poller implements Runnable {
    private volatile boolean running = true;

    public void run() {
        while (running) {
            poll();
            try {
                Thread.sleep(1000);
~>            } catch (InterruptedException e) {
                // keep polling
            }
        }
    }

    void pause() {
~>        try { Thread.sleep(50); } catch (InterruptedException ignored) { }
    }

    void poll() {}
}
