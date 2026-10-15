package com.acme;

public class Heartbeat implements Runnable {
~>    public static long lastBeat;

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            lastBeat = System.currentTimeMillis();
        }
    }
}
