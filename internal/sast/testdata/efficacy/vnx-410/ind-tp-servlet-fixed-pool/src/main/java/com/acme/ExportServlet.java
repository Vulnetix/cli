package com.acme;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/export")
public class ExportServlet extends HttpServlet {
~>    private final ExecutorService pool = Executors.newFixedThreadPool(1);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Future<String> job = pool.submit(() -> Exporter.render(req.getParameter("id")));
        try {
            resp.getWriter().write(job.get());
        } catch (Exception e) {
            resp.sendError(500);
        }
    }
}
