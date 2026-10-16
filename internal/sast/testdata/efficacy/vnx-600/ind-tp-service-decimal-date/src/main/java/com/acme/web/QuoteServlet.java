package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;

public class QuoteServlet extends HttpServlet {

    private QuoteEngine engine;

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        BigDecimal amount = new BigDecimal(req.getParameter("amount"));
        String start = req.getParameter("start");
~>        LocalDate startDate = LocalDate.parse(start);
~>        long term = Long.valueOf(req.getParameter("termMonths"));
        resp.getWriter().write(engine.quote(amount, startDate, term).toString());
    }
}
