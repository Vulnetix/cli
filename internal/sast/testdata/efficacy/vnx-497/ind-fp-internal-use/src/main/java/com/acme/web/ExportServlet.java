package com.acme.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Path base = Paths.get(System.getProperty("user.home"), ".acme", "exports");
        Files.createDirectories(base);
        boolean windows = System.getProperty("os.name").toLowerCase().startsWith("win");
        String sep = windows ? "\r\n" : "\n";
        response.setContentType("text/plain");
        response.getWriter().println("export queued" + sep);
    }
}
