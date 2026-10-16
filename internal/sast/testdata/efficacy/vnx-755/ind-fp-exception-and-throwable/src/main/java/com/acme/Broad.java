package com.acme;

public class Broad {
    void a() {
        try {
            work();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void b() {
        try {
            work();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    // catch (InterruptedException e) { } in a comment
    void work() {}
}
