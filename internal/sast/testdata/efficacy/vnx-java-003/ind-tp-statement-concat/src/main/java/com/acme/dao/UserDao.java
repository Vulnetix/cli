package com.acme.dao;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class UserDao {
    public ResultSet find(Connection c, HttpServletRequest req) throws SQLException {
        String name = req.getParameter("name");
        Statement stmt = c.createStatement();
~>        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
