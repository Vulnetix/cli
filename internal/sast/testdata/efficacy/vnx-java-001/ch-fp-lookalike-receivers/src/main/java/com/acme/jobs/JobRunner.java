package com.acme.jobs;

import javax.servlet.http.HttpServletRequest;

public class JobRunner {
    private final CommandBus commandBus;
    private final org.slf4j.Logger log = @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y][.]g[e]tL[o]gg[e]r@@(JobRunner.class);

    public JobRunner(CommandBus commandBus) { this.commandBus = commandBus; }

    public void run(HttpServletRequest request) {
        String id = request.getParameter("job");
        commandBus.exec("job-" + id);
        log.info("Runtime.getRuntime().exec(\"report \" + id) replaced by bus for " + id);
        // Runtime.getRuntime().exec("report " + id);
    }

    interface CommandBus { void exec(String name); }
}
