package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RateServlet extends HttpServlet {
    private static final int WINDOW = 60;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int secs = Math.max(1, Integer.parseInt(req.getParameter("secs")));
        int perMinute = WINDOW / secs;
        int halves = WINDOW / 2;
        resp.getWriter().println(perMinute + halves);
    }
}
