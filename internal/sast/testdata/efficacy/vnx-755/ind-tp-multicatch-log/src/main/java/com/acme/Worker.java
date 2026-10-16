package com.acme;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

public class Worker {
    private static final Logger LOG = Logger.getLogger("w");

    public void step(BlockingQueue<String> q) {
        try {
            String s = q.take();
            process(s);
~>        } catch (InterruptedException | IllegalStateException e) {
            LOG.warning("failed: " + e.getMessage());
        }
        System.out.println("continuing");
    }

    void process(String s) {}
}
