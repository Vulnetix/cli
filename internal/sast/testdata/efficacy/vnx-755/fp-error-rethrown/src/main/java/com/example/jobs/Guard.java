package com.example.jobs;

public class Guard {
    void run(Runnable r) {
        try {
            r.run();
        } catch (OutOfMemoryError e) {
            dumpState();
            throw e;
        } catch (Error e) { throw new RuntimeException(e); }
    }

    void dumpState() {}
}
