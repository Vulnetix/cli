package com.acme;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Worker {
    private static final Logger log = LoggerFactory.getLogger(Worker.class);

    public void run(Job job) {
        try {
            job.execute();
        } catch (Exception ex) {
            log.error("job {} failed", job.id(), ex);
            job.markFailed();
        }
    }

    public Result call(Job job) {
        try {
            return job.call();
        } catch (Throwable t) {
            throw new JobException("job failed", t);
        }
    }

    public Result safe(Job job) {
        try {
            return job.call();
        } catch (java.io.IOException e) {
            return Result.retry();
        }
    }
}
