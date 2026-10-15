package com.example.billing;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

public class InvoiceServlet extends HttpServlet {
    private DataSource ds;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String invoiceId = request.getParameter("invoiceId");
        try (Connection c = ds.getConnection()) {
~>            PreparedStatement ps = c.prepareStatement("SELECT amount, customer FROM invoices WHERE id = ?");
            ps.setString(1, invoiceId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                response.getWriter().println(rs.getString("customer") + " " + rs.getBigDecimal("amount"));
            }
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}
