package com.acme.jobs;

import jakarta.annotation.Resource;
import jakarta.ejb.Asynchronous;
import jakarta.ejb.Stateless;
import jakarta.enterprise.concurrent.ManagedExecutorService;

@Stateless
public class JobBean {

    @Resource
    private ManagedExecutorService executor;

    @Asynchronous
    public void run(Runnable job) {
        executor.submit(job);
    }

    public String describe() {
        return "This bean never calls new Thread() or System.exit() itself.";
    }
}
