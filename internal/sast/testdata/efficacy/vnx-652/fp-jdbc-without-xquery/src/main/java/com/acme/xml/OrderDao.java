package com.acme.xml;

import java.sql.Connection;
import java.sql.ResultSet;

public class OrderDao {
    // XQuery support was removed; this now uses JDBC.
    public ResultSet byCustomer(Connection c, String id) throws Exception {
        return c.createStatement().executeQuery("SELECT * FROM orders WHERE customer = '" + id + "'");
    }
}
