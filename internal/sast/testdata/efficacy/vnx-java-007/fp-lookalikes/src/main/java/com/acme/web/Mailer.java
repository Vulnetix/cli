package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class Mailer {
    private final Template template = new Template();

    public void send(HttpServletRequest request) {
        String target = request.getParameter("target");
        template.redirectTo(target);
        String location = request.getParameter("location");
        template.setHeader("X-Location", location);
        log("sending " + target + location);
    }

    private void log(String s) {
    }
}
