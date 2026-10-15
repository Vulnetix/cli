package com.acme.web;

import java.io.IOException;
import java.util.UUID;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class TraceServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        UUID trace = UUID.fromString(req.getHeader("X-Trace-Id"));
        resp.getWriter().println(trace);
    }
}
