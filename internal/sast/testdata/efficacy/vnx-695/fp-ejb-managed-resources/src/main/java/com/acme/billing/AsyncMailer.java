package com.acme.billing;

import java.util.concurrent.Future;
import javax.annotation.Resource;
import javax.ejb.AsyncResult;
import javax.ejb.Asynchronous;
import javax.ejb.Stateless;
import javax.enterprise.concurrent.ManagedExecutorService;

@Stateless
public class AsyncMailer {

    @Resource
    private ManagedExecutorService executor;

    @Asynchronous
    public Future<Boolean> send(Mail m) {
        executor.submit(() -> deliver(m));
        return new AsyncResult<>(true);
    }

    private void deliver(Mail m) {}
}
