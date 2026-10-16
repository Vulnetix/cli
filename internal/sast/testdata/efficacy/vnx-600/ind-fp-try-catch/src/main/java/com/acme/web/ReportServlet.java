package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;

public class ReportServlet extends HttpServlet {

    private ReportService reports;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String from = request.getParameter("from");
        String limit = request.getParameter("limit");
        try {
            LocalDate fromDate = LocalDate.parse(from);
            int max = Integer.parseInt(limit);
            response.getWriter().write(reports.since(fromDate, max));
        } catch (DateTimeParseException | NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid from or limit");
        }
    }
}
