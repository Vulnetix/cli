package com.acme.export;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportServlet extends HttpServlet {

    private final ReportService reports = new ReportService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String countParam = req.getParameter("count");
        int count = Integer.parseInt(countParam);
        resp.setContentType("text/csv");
        PrintWriter out = resp.getWriter();
        out.println("id,name,total");
~>        for (int i = 0; i < count; i++) {
            out.println(reports.row(i));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        long pages = Long.parseLong(req.getHeader("X-Page-Count"));
        long p = 0;
~>        while (p < pages) {
            reports.renderPage(p);
            p++;
        }
        resp.setStatus(204);
    }
}
