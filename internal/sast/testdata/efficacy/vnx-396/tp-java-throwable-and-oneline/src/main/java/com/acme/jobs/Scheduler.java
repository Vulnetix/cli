package com.acme.jobs;

public class Scheduler {
    private volatile boolean healthy = true;

    public void tick(Job job) {
        try {
            job.run();
~>        } catch (final Throwable t) {
            healthy = false;
        }
    }

    public int pending() {
~>        try { return queue.size(); } catch (java.lang.Exception e) { return 0; }
    }
}
