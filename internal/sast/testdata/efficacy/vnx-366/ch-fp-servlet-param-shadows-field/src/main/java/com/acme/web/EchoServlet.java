package com.acme.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoServlet extends HttpServlet {
    private String resp;

    @Override
    public void init() throws ServletException {
        resp = "ready";
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        resp.setContentType("text/plain");
        resp = wrap(resp);
        resp.getWriter().println(req.getParameter("q"));
    }

    private HttpServletResponse wrap(HttpServletResponse r) {
        return r;
    }
}
