package com.acme;

import java.util.concurrent.ExecutorService;

public class Notes {
    private ExecutorService pool;

    // pool.submit(() -> work()); was removed because the future was lost
    // CompletableFuture.runAsync(this::work);
    String doc = "call pool.submit(task) and keep the Future";
}
