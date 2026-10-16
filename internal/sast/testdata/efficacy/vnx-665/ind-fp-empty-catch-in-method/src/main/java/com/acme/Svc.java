package com.acme;

public class Svc {
    public void close(java.io.Closeable c) {
        try {
            c.close();
        } catch (Exception e) {
        }
    }

    public void run() {
        try {
            work();
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }
}
