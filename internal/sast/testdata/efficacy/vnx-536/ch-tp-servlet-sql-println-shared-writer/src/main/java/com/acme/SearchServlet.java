package com.acme;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import javax.servlet.http.*;

public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        try (Connection c = ds.getConnection()) {
            ResultSet rs = c.createStatement().executeQuery("SELECT 1");
            out.println("ok");
        } catch (SQLException sqle) {
~>            out.println("Query failed: " + sqle.getMessage());
        }
    }
}
