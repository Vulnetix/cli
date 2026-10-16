package com.acme.jobs;

public class JobRunner {

    public void run(Job job) {
        String action = job.getAction();
~>        if (action ==
                "purge") {
            job.purgeAll();
        } else {
            job.execute();
        }
    }
}
