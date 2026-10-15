package com.acme.web;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/status")
public class StatusResource {
    private static final ThreadLocal<StringBuilder> BUF = new ThreadLocal<>();

    @GET
    public String status() {
        Thread[] all = new Thread[Thread.activeCount()];
        Thread.currentThread().setName("status");
        int code = exitCode();
        return "exit code " + code + " via System.exit(" + code + ")";
    }

    private int exitCode() {
        return 0;
    }
}
