package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class Rate {
    public long perSecond(HttpServletRequest req, long bytes) {
        int secs = Math.max(1, Integer.parseInt(req.getParameter("secs")));
        return bytes / secs;
    }
}
