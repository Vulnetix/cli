package com.acme.jobs;

import java.util.concurrent.Executor;

public class InlineExecutor implements Executor {
    @Override
    public void execute(Runnable command) {
        command.run();
    }

    public void runTask(Runnable task) {
        Runnable wrapped = () -> task.run();
        wrapped.run();
    }
}
