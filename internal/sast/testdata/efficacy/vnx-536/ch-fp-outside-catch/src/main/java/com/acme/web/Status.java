package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;

public class Status extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Result r = check();
        resp.getWriter().println(r.getMessage());
        // catch (Exception e) { resp.getWriter().println(e.getMessage()); }
    }
}
