package com.acme.reports;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    private static final String REPORT_DIR = "/srv/reports";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/pdf");
~>        try (InputStream in = new FileInputStream(REPORT_DIR + "/" + request.getParameter("report") + ".pdf")) {
            in.transferTo(response.getOutputStream());
        }
    }
}
