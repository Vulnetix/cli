package com.acme;
import java.io.*;
import java.util.logging.*;
public class Handled {
    private static final Logger LOG = Logger.getLogger("h");
    void a(Closeable c) {
        try {
            c.close();
        } catch (IOException e) {
            // already closed, nothing to do
        }
    }
    void b(Closeable c) {
        try { c.close(); } catch (IOException e) { LOG.log(Level.WARNING, "close", e); }
    }
    void c() {
        try { Thread.sleep(5); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
    void d() {
        try { run(); } catch (RuntimeException e) { throw new IllegalStateException(e); }
    }
    void run() {}
}
