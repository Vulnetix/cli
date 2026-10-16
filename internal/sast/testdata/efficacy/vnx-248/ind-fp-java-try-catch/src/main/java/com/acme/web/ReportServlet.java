package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    private static final int DEFAULT_YEAR = Integer.parseInt("2024");
    private final int poolSize = Integer.parseInt(System.getProperty("report.pool", "4"));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int year;
        try {
            year = Integer.parseInt(request.getParameter("year"));
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "year must be a number");
            return;
        }
        String q = request.getParameter("quarter");
        if (q == null || !q.matches("[1-4]")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        int quarter = Integer.parseInt(q);
        response.getWriter().write(Reports.render(year, quarter, poolSize));
    }
}
