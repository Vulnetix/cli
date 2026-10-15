package com.acme.users;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserDao {
    private Connection conn;

    public ResultSet find(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", name);
        Statement stmt = conn.createStatement();
~>        return stmt.executeQuery(sql);
    }
}
