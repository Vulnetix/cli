package com.acme.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HitServlet extends HttpServlet {
~>    private static int hits = 0;
~>    private static Map<String, Integer> perUser = new HashMap<>();
    private static final String HEADER = "X-Hits";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        hits++;
        String user = req.getRemoteUser();
        perUser.put(user, perUser.getOrDefault(user, 0) + 1);
        resp.setHeader(HEADER, String.valueOf(hits));
    }
}
