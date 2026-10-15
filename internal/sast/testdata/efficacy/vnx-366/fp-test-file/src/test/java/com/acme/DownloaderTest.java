package com.acme;

public class DownloaderTest implements Runnable {
    static int calls;

    public void run() {
        calls++;
    }

    void start() {
        new Thread(this).start();
    }
}
