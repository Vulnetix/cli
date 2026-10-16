package com.acme.web;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ExportServlet extends HttpServlet {

    private static final String DEFAULT_ROWS = "500";
    private int maxRows;

    @Override
    public void init() throws ServletException {
        maxRows = Integer.parseInt(getServletConfig().getInitParameter("maxRows"));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int rows = Integer.parseInt(DEFAULT_ROWS);
        long timeout = Long.parseLong(System.getProperty("export.timeout.ms", "30000"));
        resp.getWriter().write("rows=" + Math.min(rows, maxRows) + " timeout=" + timeout);
    }
}
