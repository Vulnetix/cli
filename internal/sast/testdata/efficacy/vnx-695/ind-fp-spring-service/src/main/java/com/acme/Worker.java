package com.acme;

import org.springframework.stereotype.Service;

@Service
public class Worker {
    private int n;

    public void start(Runnable r) {
        new Thread(r).start();
        System.exit(0);
    }

    public synchronized void inc() { n++; }
}
