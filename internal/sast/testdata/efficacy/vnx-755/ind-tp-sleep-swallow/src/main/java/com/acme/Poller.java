package com.acme;

public class Poller {
    public void poll() {
        while (!ready()) {
            try {
                Thread.sleep(1000);
~>            } catch (InterruptedException e) {
                // keep polling
            }
        }
    }
    boolean ready() { return false; }
}
