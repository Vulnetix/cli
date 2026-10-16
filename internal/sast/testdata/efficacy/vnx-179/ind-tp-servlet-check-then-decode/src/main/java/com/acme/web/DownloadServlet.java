package com.acme.web;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {

    private static final Path BASE = Paths.get("/var/app/files");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String file = req.getPathInfo();
~>        if (file == null || file.contains("..")) {
            resp.sendError(400);
            return;
        }
        String name = URLDecoder.decode(file, StandardCharsets.UTF_8);
        Files.copy(BASE.resolve(name.substring(1)), resp.getOutputStream());
    }
}
