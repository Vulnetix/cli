package com.acme.index;

public class LoggingThread extends Thread {
    public LoggingThread(Runnable r) {
        super(r);
    }

    @Override
    public void run() {
        long t0 = System.nanoTime();
        super.run();
        System.out.println("took " + (System.nanoTime() - t0));
    }
}
