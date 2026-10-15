package com.acme.net;

import java.io.IOException;
import java.util.logging.Logger;

public class Pool {
    private static final Logger LOG = Logger.getLogger("pool");

    public void release(Conn c) {
        try {
            c.close();
        } catch (IOException e) {
            LOG.warning("close failed: " + e);
        } finally {
        }
    }

    public void stop(Thread t) {
        try {
            t.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void drain(Queue q) {
        try {
            q.drain();
        } catch (IOException ignored) {
        }
    }
}
