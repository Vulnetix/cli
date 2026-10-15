package com.acme.sync;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class Syncer {
    private final ExecutorService executor;
    private final Map<String, Remote> remotes;

    public Syncer(ExecutorService executor, Map<String, Remote> remotes) {
        this.executor = executor;
        this.remotes = remotes;
    }

    public void push(String name, Batch b) {
~>        executor.submit(() -> remotes.get(name).push(b));
~>        CompletableFuture.runAsync(() -> {
            Remote r = remotes.get(name);
            r.flush();
        }, executor);
    }
}
