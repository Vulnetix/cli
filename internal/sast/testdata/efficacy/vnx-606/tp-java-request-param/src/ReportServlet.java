package com.example.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        int rows = Integer.parseInt(request.getParameter("rows"));
        StringBuilder sb = new StringBuilder();
~>        for (int i = 0; i < rows; i++) {
            sb.append(render(i));
        }
        String raw = request.getHeader("X-Pages");
        long pages = Long.parseLong(raw);
~>        for (long p = 0; p < pages; p++) {
            sb.append(page(p));
        }
        response.getWriter().write(sb.toString());
    }
}
