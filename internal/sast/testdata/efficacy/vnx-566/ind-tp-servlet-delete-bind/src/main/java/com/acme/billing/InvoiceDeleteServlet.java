package com.acme.billing;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

public class InvoiceDeleteServlet extends HttpServlet {
    private DataSource dataSource;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String invoiceId = req.getParameter("invoice");
        try (Connection c = dataSource.getConnection()) {
~>            PreparedStatement ps = c.prepareStatement("DELETE FROM invoices WHERE id = ?");
            ps.setLong(1, Long.parseLong(invoiceId));
            ps.executeUpdate();
        } catch (SQLException e) {
            resp.sendError(500);
            return;
        }
        resp.setStatus(204);
    }
}
