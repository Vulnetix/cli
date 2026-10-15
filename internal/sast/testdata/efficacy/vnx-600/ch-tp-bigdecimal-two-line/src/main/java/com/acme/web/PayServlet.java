package com.acme.web;

import java.io.IOException;
import java.math.BigDecimal;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PayServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String raw = req.getParameter("amount");
~>        BigDecimal amount = new BigDecimal(raw);
        ledger.charge(amount);
    }
}
