package com.acme.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class SafeUserDao {
    private Connection conn;

    public ResultSet find(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM users WHERE name = ? AND active = ?");
        ps.setString(1, name);
        ps.setBoolean(2, true);
        return ps.executeQuery();
    }
}
