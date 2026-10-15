package com.acme.net;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class PingController {
    public String ping(HttpServletRequest request) throws IOException {
        Runtime rt = Runtime.getRuntime();
        String host = request.getParameter("host");
        String cmd = String.format("ping -c 1 %s", host);
~>        Process p = rt.exec(cmd);
        return readAll(p);
    }

    private String readAll(Process p) { return ""; }
}
