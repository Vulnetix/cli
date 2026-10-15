package com.example.jobs;

public class Writer {
    void start() {
        Thread t = new Thread("writer") {
            @Override public void run() {
                try {
                    Thread.sleep(10);
                    emit();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
        t.start();
    }

    void emit() {}
}
