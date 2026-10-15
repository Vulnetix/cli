package com.acme.report;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public class ReportService {
    private final Executor pool;
    private final ReportStore store;

    public ReportService(Executor pool, ReportStore store) {
        this.pool = pool;
        this.store = store;
    }

    public void regenerate(String id) {
~>        CompletableFuture.runAsync(() -> {
            Report r = store.load(id);
            store.save(r.rebuild());
        }, pool);
    }

    public void warm(String id) {
~>        CompletableFuture.supplyAsync(() -> store.load(id), pool)
                .thenAccept(store::cache);
    }
}
