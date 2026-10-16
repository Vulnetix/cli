package com.acme;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.*;

public class HitServlet extends HttpServlet {
~>    private static int hits = 0;
~>    private static Map<String, Integer> perUser = new HashMap<>();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        hits++;
        perUser.put(req.getRemoteUser(), hits);
        resp.getWriter().println(hits);
    }
}
