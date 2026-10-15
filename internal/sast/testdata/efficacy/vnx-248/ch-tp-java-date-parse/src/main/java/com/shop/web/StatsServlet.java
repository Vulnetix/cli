package com.shop.web;

import java.time.LocalDate;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatsServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String from = request.getParameter("from");
~>        LocalDate start = LocalDate.parse(from);
~>        double ratio = Double.parseDouble(request.getHeader("X-Ratio"));
        render(response, stats.since(start, ratio));
    }
}
