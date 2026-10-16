package com.acme.web;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Connection con = ds.getConnection();
~>        PreparedStatement ps = con.prepareStatement("SELECT * FROM invoices WHERE id = ?");
        ps.setString(1, req.getParameter("id"));
        ps.executeQuery();
    }
}
