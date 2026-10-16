package com.acme.web;

import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RoleSwitchServlet extends HttpServlet {
    private static final Set<String> ALLOWED_VIEWS = Set.of("grid", "list", "compact");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String view = req.getParameter("view");
        if (!ALLOWED_VIEWS.contains(view)) {
            resp.sendError(400);
            return;
        }
        req.getSession().setAttribute("view", view);
    }
}
