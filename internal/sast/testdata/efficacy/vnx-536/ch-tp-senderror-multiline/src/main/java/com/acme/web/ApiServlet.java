package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;

public class ApiServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            handle(req, resp);
        } catch (IllegalStateException err) {
~>            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, err.getMessage());
        }
    }
}
