package com.shop.web;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.UUID;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class OrderServlet extends HttpServlet {
    @Override
    public void doPost(final HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String qty = req.getParameter("qty");
        String amount = req.getParameter("amount");
~>        int n = Integer.valueOf(qty);
~>        BigDecimal total = new BigDecimal(amount);
        resp.setStatus(200);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String ref = req.getHeader("X-Order-Ref");
~>        UUID orderId = UUID.fromString(ref);
        super.service(req, resp);
    }
}
