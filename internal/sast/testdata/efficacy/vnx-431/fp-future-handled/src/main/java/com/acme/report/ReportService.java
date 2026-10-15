package com.acme.report;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class ReportService {
    private final ExecutorService pool;
    private final ReportStore store;
    private final Log log;

    public ReportService(ExecutorService pool, ReportStore store, Log log) {
        this.pool = pool;
        this.store = store;
        this.log = log;
    }

    public void regenerate(String id) {
        CompletableFuture.runAsync(() -> {
            store.save(store.load(id).rebuild());
        }, pool).exceptionally(ex -> {
            log.error("rebuild failed", ex);
            return null;
        });
    }

    public CompletableFuture<Report> load(String id) {
        return CompletableFuture.supplyAsync(() -> store.load(id), pool);
    }

    public Future<?> start(String id) {
        Future<?> f = pool.submit(() -> store.load(id));
        return f;
    }

    public void warm(String id) {
        CompletableFuture.supplyAsync(() -> store.load(id), pool)
                .whenComplete((r, ex) -> log.info("done"));
        pool.execute(() -> store.load(id));
    }
}
