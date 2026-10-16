package com.acme.watch;

public class Watchdog {
    private final Thread monitor;

    public Watchdog(Runnable probe) {
        this.monitor = new Thread(probe, "watchdog");
        this.monitor.setDaemon(true);
    }

    public void begin() {
~>        monitor.run();
    }
}
