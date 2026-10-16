package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {

    private static final String ROOT = "/srv/app/downloads";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        File f = new File(ROOT, req.getParameter("name"));
~>        if (!f.getAbsolutePath().startsWith(ROOT)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
