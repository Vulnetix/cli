package com.acme.export;

import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BoundedServlet extends HttpServlet {

    private static final int MAX_ROWS = 500;
    private final ReportService reports = new ReportService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int rows = Math.min(Integer.parseInt(req.getParameter("rows")), MAX_ROWS);
        for (int i = 0; i < rows; i++) {
            resp.getWriter().println(reports.row(i));
        }

        int pages = Integer.parseInt(req.getParameter("pages"));
        if (pages > 20 || pages < 0) {
            resp.sendError(400, "pages out of range");
            return;
        }
        for (int p = 0; p < pages; p++) {
            reports.renderPage(p);
        }

        List<String> ids = reports.ids();
        for (int i = 0; i < ids.size(); i++) {
            resp.getWriter().println(ids.get(i));
        }
    }

    // Parsed here, looped elsewhere: not the same function.
    int parseLimit(HttpServletRequest req) {
        return Integer.parseInt(req.getParameter("limit"));
    }

    void emit(int limit) {
        for (int i = 0; i < limit; i++) {
            reports.renderPage(i);
        }
    }
}
