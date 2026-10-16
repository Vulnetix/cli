package com.acme.web;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OrderStatusServlet extends HttpServlet {

    private OrderService orders;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String ref = req.getHeader("X-Order-Ref");
        resp.setContentType("application/json");
~>        UUID orderId = UUID.fromString(ref);
        resp.getWriter().write(orders.statusJson(orderId));
    }
}
