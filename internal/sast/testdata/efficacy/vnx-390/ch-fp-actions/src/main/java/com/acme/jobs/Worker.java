package com.acme.jobs;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Worker {
    private static final Logger LOG = Logger.getLogger(Worker.class.getName());

    public void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    public Integer parse(String s) {
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public void step(Job job) {
        for (int i = 0; i < 3; i++) {
            try {
                job.run();
                break;
            } catch (Exception e) {
                LOG.log(Level.FINE, "retrying", e);
            }
        }
    }
}
