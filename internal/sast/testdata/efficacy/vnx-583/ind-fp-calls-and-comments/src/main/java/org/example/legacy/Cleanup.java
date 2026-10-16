package org.example.legacy;

/**
 * Historical note: this used to declare public void finalize() which let
 * callers free the resource early.
 */
public class Cleanup {
    // public void finalize() { }
    private static final String DOC = "public void finalize() is wrong";

    void run(Session s) throws Throwable {
        s.finalize();
    }
}
