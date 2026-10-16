package com.acme;

import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;

public class SafeServlet extends HttpServlet {
    private static final Path BASE = Paths.get("/var/data/reports").toAbsolutePath().normalize();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("file");
        Path resolved = BASE.resolve(name).normalize();
        if (!resolved.startsWith(BASE)) {
            response.sendError(403);
            return;
        }
        Files.copy(resolved, response.getOutputStream());
    }
}
