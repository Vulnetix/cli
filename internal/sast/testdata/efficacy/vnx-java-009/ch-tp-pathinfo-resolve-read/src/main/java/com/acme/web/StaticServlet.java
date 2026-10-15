package com.acme.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StaticServlet extends HttpServlet {
    private final Path root = Paths.get("/var/www/static");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String rel = req.getPathInfo();
        String trimmed = rel.substring(1);
~>        Path target = root.resolve(trimmed);
        byte[] body = Files.readAllBytes(target);
        resp.getOutputStream().write(body);
    }
}
