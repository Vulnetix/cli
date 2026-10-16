package com.acme.docs;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class PreviewServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        if (req.getParameter("mode") == "draft") {
            resp.setHeader("Cache-Control", "no-store");
        }
        resp.getWriter().write(render(req.getPathInfo()));
    }

    private String render(String path) {
        return "<p>" + path + "</p>";
    }
}
