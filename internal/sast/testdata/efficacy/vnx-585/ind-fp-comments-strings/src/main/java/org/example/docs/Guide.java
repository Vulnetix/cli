package org.example.docs;

/**
 * Never write synchronized (lock) {} to wait for another thread.
 */
public class Guide {
    // synchronized (lock) { }
    static final String BAD = "synchronized (lock) {}";

    void ok(Object lock, java.util.List<String> out) {
        synchronized (lock) {
            out.add(BAD);
        }
    }
}
