package com.acme.jobs;

import java.util.concurrent.ExecutorService;

public class Runner {
    void run(ExecutorService pool, Job job) {
        try {
            job.execute();
        } finally {
            pool.submit(() -> {
                return job.cleanup();
            });
            pool.submit(new java.util.concurrent.Callable<Integer>() {
                @Override
                public Integer call() {
                    return job.id();
                }
            });
        }
    }
}
