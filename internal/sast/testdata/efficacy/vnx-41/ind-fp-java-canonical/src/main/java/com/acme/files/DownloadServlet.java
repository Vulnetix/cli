package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {

    private static final String ROOT = "/srv/app/downloads/";
    private final Path base = Paths.get("/var/lib/archive").toAbsolutePath().normalize();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        File f = new File(ROOT, req.getParameter("name"));
        if (!f.getCanonicalPath().startsWith(ROOT)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        Path target = base.resolve(req.getParameter("entry")).normalize();
        if (!target.startsWith(base)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
