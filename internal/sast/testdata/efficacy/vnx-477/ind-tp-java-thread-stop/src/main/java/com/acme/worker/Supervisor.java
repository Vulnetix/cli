package com.acme.worker;

public class Supervisor {
    private Thread workerThread;

    public void shutdownNow() {
        if (workerThread != null && workerThread.isAlive()) {
~>            workerThread.stop();
        }
    }
}
