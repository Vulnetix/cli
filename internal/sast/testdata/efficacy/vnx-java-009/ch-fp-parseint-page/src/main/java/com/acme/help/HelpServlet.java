package com.acme.help;

import java.io.File;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelpServlet extends HttpServlet {
    private final File base = new File("/opt/help");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        int page = Integer.parseInt(req.getParameter("page"));
        File f = new File(base, "page-" + page + ".html");
        resp.getWriter().write(Files.readString(f.toPath()));
    }
}
