package com.acme.search;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class Indexer {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Indexer.class);
    private final ExecutorService pool;
    private final List<Future<?>> pending = new ArrayList<>();

    Indexer(ExecutorService pool) {
        this.pool = pool;
    }

    public void reindex(long id) {
        CompletableFuture.runAsync(() -> engine.reindex(id), pool)
            .whenComplete((v, ex) -> {
                if (ex != null) {
                    log.warn("reindex {} failed", id, ex);
                }
            });
    }

    public CompletableFuture<Stats> stats() {
        return CompletableFuture.supplyAsync(engine::stats, pool);
    }

    public void enqueue(Runnable job) {
        Future<?> f = pool.submit(job);
        pending.add(f);
        pending.add(CompletableFuture.runAsync(job, pool));
    }

    public void fireAndForget(Runnable job) {
        pool.execute(job);
    }
}
