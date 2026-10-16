package com.acme.billing;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class InvoiceRepository {
    public ResultSet find(Connection c, HttpServletRequest request, long customerId) throws SQLException {
        String invoiceId = request.getParameter("invoiceId");
        PreparedStatement ps = c.prepareStatement(
            "SELECT amount, due_date FROM invoices WHERE id = ?"
                + " AND customer_id = ?");
        ps.setString(1, invoiceId);
        ps.setLong(2, customerId);
        return ps.executeQuery();
    }
}
