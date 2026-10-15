package com.acme.batch;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Fanout {
    private final ExecutorService pool = Executors.newWorkStealingPool();
    private final Queue queue;

    public Fanout(Queue queue) {
        this.queue = queue;
    }

    public List<Future<Integer>> run(List<Job> jobs) {
        List<Future<Integer>> out = new ArrayList<>();
        for (Job j : jobs) {
            out.add(pool.submit(j::execute));
        }
        CompletableFuture<Void> all = CompletableFuture.runAsync(this::drain, pool);
        queue.submit(new Ticket());
        return out;
    }

    private void drain() {
    }
}
