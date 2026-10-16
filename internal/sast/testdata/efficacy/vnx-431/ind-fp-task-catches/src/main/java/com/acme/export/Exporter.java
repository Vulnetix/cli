package com.acme.export;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class Exporter {
    private final ExecutorService workers;

    Exporter(ExecutorService workers) {
        this.workers = workers;
    }

    public void flushLater() {
        CompletableFuture.runAsync(() -> {
            try {
                sink.flush();
            } catch (Exception e) {
                log.error("flush failed", e);
            }
        }, workers);
    }

    public void submitForm(HtmlForm form, JobQueue jobQueue, Job job) {
        form.submit();
        jobQueue.submit(job);
    }
}
