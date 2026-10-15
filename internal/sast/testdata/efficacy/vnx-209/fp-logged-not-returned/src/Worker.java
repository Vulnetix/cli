package com.shop;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Worker {
    private static final Logger log = LoggerFactory.getLogger(Worker.class);

    public Result run() {
        try {
            return task.call();
        } catch (Exception e) {
            e.printStackTrace();
            log.error("task failed", e);
            return Result.failed("internal error");
        }
    }
}
