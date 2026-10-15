package com.example.jobs;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Waiter {
    private static final Logger LOG = LoggerFactory.getLogger(Waiter.class);

    String await(Future<String> f) {
        String result = null;
        try {
            result = f.get();
~>        } catch (final InterruptedException | ExecutionException e) {
            LOG.warn("wait failed", e);
        }
        return result;
    }
}
