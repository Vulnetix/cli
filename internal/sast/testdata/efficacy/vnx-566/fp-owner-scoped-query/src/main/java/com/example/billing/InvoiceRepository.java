package com.example.billing;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class InvoiceRepository {
    public ResultSet find(Connection c, HttpServletRequest request, long customerId) throws Exception {
        String invoiceId = request.getParameter("invoiceId");
        PreparedStatement ps = c.prepareStatement("SELECT amount FROM invoices WHERE id = ? AND customer_id = ?");
        ps.setString(1, invoiceId);
        ps.setLong(2, customerId);
        return ps.executeQuery();
    }

    public ResultSet findSplit(Connection c, HttpServletRequest request, long customerId) throws Exception {
        String invoiceId = request.getParameter("invoiceId");
        PreparedStatement ps = c.prepareStatement("SELECT amount FROM invoices WHERE id = ? "
                + "AND customer_id = ?");
        ps.setString(1, invoiceId);
        ps.setLong(2, customerId);
        return ps.executeQuery();
    }
}
