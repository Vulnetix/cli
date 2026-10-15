package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;

public class SafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            handle(req, resp);
        } catch (Exception e) {
            log.error("handler failed: {}", e.getMessage(), e);
            e.printStackTrace();
            resp.sendError(500, "Internal error");
            resp.getWriter().println("Request failed, reference " + requestId);
        }
    }
}
