package com.example.work;

public class Ticker {
    private volatile boolean running = true;

    public void loop() {
        while (running) {
            tick();
            try {
                Thread.sleep(100);
~>            } catch (InterruptedException e) {
                continue;
            }
            System.out.println("tick done");
        }
    }

    private void tick() { }
}
