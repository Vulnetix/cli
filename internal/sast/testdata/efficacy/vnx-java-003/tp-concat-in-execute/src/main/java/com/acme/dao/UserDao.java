package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserDao {
    private Connection connection;

    public ResultSet find(HttpServletRequest request) throws SQLException {
        String name = request.getParameter("name");
        Statement stmt = connection.createStatement();
~>        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
~>        stmt.executeUpdate("DELETE FROM sessions WHERE token='"+request.getParameter("t")+"'");
~>        stmt.execute("UPDATE users SET seen = 1 WHERE id = " + request.getParameter("id"));
        return rs;
    }
}
