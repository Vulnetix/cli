package com.example;

class LedgerTest {
    public final Object lock = new Object();

    void run() {
        synchronized ("test") {
            System.out.println("x");
        }
    }
}
