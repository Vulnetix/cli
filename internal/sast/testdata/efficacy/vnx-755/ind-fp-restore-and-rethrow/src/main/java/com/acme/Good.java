package com.acme;

public class Good {
    void a() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    void b() throws Exception {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            throw new IllegalStateException("interrupted", e);
        }
    }

    int c() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            return -1;
        }
        return 0;
    }

    void d() {
        try {
            throw new StackOverflowError();
        } catch (StackOverflowError e) {
            cleanup();
            throw e;
        }
    }

    void cleanup() {}
}
