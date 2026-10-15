package com.acme.sync;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public class SafeSyncer {
    private final ExecutorService executor;
    private final Log log;

    public SafeSyncer(ExecutorService executor, Log log) {
        this.executor = executor;
        this.log = log;
    }

    public void push(Batch b) throws Exception {
        executor.submit(() -> b.send()).get(30, TimeUnit.SECONDS);
        CompletableFuture.runAsync(b::send, executor).exceptionally(ex -> {
            log.error("push failed", ex);
            return null;
        });
        CompletableFuture.supplyAsync(b::size)
            .thenApply(n -> n * 2)
            .handle((n, ex) -> ex == null ? n : -1);
        CompletableFuture.runAsync(b::send).join();
    }
}
