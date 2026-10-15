package com.acme.jobs;

import java.util.List;

public class Runner {
    public void runAll(List<Job> jobs) {
        jobs.forEach(job -> {
            try {
                job.run();
~>            } catch (final java.util.concurrent.TimeoutException timeout) {

            }
        });
    }
}
