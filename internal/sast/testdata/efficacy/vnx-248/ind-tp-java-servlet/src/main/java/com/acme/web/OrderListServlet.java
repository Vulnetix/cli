package com.acme.web;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OrderListServlet extends HttpServlet {
    private final OrderService orders = new OrderService();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        int page = Integer.parseInt(request.getParameter("page"));
        String tenantHeader = request.getHeader("X-Tenant-Id");
~>        UUID tenant = UUID.fromString(tenantHeader);
        response.setContentType("application/json");
        response.getWriter().write(orders.list(tenant, page).toJson());
    }
}
