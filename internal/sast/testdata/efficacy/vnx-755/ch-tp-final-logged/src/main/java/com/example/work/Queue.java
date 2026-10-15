package com.example.work;

import java.util.concurrent.BlockingQueue;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Queue {
    private static final Logger log = LoggerFactory.getLogger(Queue.class);
    private final BlockingQueue<String> q;

    Queue(BlockingQueue<String> q) { this.q = q; }

    public String next() {
        String item = null;
        try {
            item = q.take();
~>        } catch (final InterruptedException ex) {
            log.warn("interrupted while waiting", ex);
        }
        return item;
    }
}
