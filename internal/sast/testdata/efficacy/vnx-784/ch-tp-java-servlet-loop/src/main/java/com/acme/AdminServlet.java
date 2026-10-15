package com.acme;

import javax.servlet.http.*;

public class AdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        boolean admin = false;
        for (Cookie c : req.getCookies()) {
~>            if (c.getName().equals("role") && c.getValue().equals("admin")) {
                admin = true;
            }
        }
        if (!admin) resp.sendError(403);
    }
}
