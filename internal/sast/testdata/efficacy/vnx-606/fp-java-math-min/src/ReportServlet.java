package com.example.web;

import javax.servlet.http.HttpServletRequest;

public class ReportServlet {
    private static final int MAX_ROWS = 500;

    protected String rows(HttpServletRequest request) {
        int rows = Integer.parseInt(request.getParameter("rows"));
        rows = Math.min(rows, MAX_ROWS);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows; i++) {
            sb.append(i);
        }
        int pages = Integer.parseInt(request.getParameter("pages"));
        if (pages < 0 || pages > 20) {
            throw new IllegalArgumentException("pages");
        }
        for (int p = 0; p < pages; p++) {
            sb.append(p);
        }
        return sb.toString();
    }
}
