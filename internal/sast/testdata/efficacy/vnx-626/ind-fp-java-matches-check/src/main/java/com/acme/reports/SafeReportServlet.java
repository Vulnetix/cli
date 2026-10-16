package com.acme.reports;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeReportServlet extends HttpServlet {
    private final File reportDir = new File("/srv/reports");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        if (name == null || !name.matches("[A-Za-z0-9_-]{1,64}")) {
            response.sendError(400);
            return;
        }
        File f = new File(reportDir, name + ".txt");
        Files.copy(f.toPath(), response.getOutputStream());
    }
}
