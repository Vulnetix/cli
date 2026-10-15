package com.acme.io;

public class LeakTest {
    static class Tracker {
        public void finalize() {
            System.out.println("collected");
        }
    }
}
