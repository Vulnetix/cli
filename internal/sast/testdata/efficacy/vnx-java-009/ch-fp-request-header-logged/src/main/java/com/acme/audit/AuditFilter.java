package com.acme.audit;

import java.io.FileWriter;
import javax.servlet.http.HttpServletRequest;

public class AuditFilter {
    private static final String LOG = "/var/log/acme/audit.log";

    public void record(HttpServletRequest request) throws Exception {
        String agent = request.getHeader("User-Agent");
        try (FileWriter w = new FileWriter(LOG, true)) {
            w.write(agent + "\n");
        }
    }
}
