package com.example.work;

public class Poller {
    public void pause(long ms) {
~>        try { Thread.sleep(ms); } catch (InterruptedException ignored) { }
        System.out.println("resumed");
    }
}
