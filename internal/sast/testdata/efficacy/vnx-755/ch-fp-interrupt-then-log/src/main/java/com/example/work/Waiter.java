package com.example.work;

import java.util.concurrent.CountDownLatch;

public class Waiter {
    public boolean await(CountDownLatch latch) {
        try {
            latch.await();
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("interrupted");
            return false;
        }
    }
}
