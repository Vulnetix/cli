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
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String report = req.getParameter("report");
        Path p = Paths.get("/var/reports", report);
~>        byte[] data = Files.readAllBytes(p);
        resp.setContentType("application/pdf");
        resp.getOutputStream().write(data);
    }
}
