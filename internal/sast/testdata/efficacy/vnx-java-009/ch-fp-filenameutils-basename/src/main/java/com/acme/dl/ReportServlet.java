package com.acme.dl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FilenameUtils;

public class ReportServlet extends HttpServlet {
    private static final File REPORTS = new File("/srv/reports");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String safe = FilenameUtils.getName(request.getParameter("report"));
        File f = new File(REPORTS, safe);
        String other = Paths.get(request.getParameter("name")).getFileName().toString();
        byte[] body = Files.readAllBytes(REPORTS.toPath().resolve(other));
        response.getOutputStream().write(Files.readAllBytes(f.toPath()));
        response.getOutputStream().write(body);
    }
}
