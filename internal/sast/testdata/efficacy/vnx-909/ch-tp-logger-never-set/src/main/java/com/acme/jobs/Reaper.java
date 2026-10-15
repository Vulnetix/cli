package com.acme.jobs;

import java.util.logging.Logger;

public class Reaper implements Runnable {
~>    private Logger logger;
    private final int limit;

    public Reaper(int limit) {
        this.limit = limit;
    }

    @Override
    public void run() {
        logger.info("reaping up to " + limit);
    }
}
