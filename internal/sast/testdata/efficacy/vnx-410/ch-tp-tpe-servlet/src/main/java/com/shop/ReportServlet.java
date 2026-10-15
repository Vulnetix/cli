package com.shop;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
~>    private final ThreadPoolExecutor pool = new ThreadPoolExecutor(1, 1, 0L,
            TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        pool.submit(() -> render(req.getParameter("id")));
    }
}
