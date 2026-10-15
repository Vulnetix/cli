package com.acme.jobs;

public class Runner {
    boolean run(Job job) {
        try {
            job.execute();
        } catch (RuntimeException e) {
            throw e;
        }
        finally
        {
            if (job.isDirty()) {
~>                return false;
            }
            job.cleanup();
        }
        return true;
    }

    String name(Job job) {
~>        try { return job.name(); } finally { return "unknown"; }
    }
}
