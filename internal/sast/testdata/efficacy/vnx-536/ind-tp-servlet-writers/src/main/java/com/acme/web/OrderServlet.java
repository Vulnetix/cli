package com.acme.web;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;

public class OrderServlet extends HttpServlet {

    private final OrderService orders = new OrderService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        PrintWriter out = resp.getWriter();
        try {
            out.println(orders.render(req.getParameter("id")));
        } catch (SQLException e) {
            resp.setStatus(500);
~>            out.println("Database error: " + e.getMessage());
        } catch (IllegalStateException ex) {
~>            ex.printStackTrace(resp.getWriter());
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            orders.create(request.getReader());
        } catch (Exception e) {
~>            response.sendError(500, e.getLocalizedMessage());
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try {
            orders.delete(request.getParameter("id"));
        } catch (RuntimeException failure) {
            response.setContentType("text/plain");
~>            response.getWriter().write(failure.toString());
        }
    }
}
