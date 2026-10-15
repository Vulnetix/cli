package com.acme.jobs;

import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;

@Component
public class ReindexJob {
    private final ThreadPoolTaskExecutor taskExecutor;
    private final SearchIndex index;

    public ReindexJob(ThreadPoolTaskExecutor taskExecutor, SearchIndex index) {
        this.taskExecutor = taskExecutor;
        this.index = index;
    }

    public void trigger() {
~>        taskExecutor.submit(index::rebuild);
    }
}
