package com.acme.util;

import java.io.IOException;

public class Shell {
    private final TaskRunner runner = new TaskRunner();

    // A wrapper: what reaches it is decided by its callers.
    public Process run(String command) throws IOException {
        return Runtime.getRuntime().exec(command);
    }

    public void schedule(String job) {
        runner.exec(job + "-nightly");
        Runtime rt = Runtime.getRuntime();
        long free = rt.freeMemory() + rt.totalMemory();
        System.out.println("free " + free);
    }
}
