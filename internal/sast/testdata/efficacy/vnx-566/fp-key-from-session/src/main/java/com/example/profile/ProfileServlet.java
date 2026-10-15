package com.example.profile;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class ProfileServlet {
    public ResultSet me(Connection c, HttpServletRequest request) throws Exception {
        HttpSession session = request.getSession(false);
        String uid = (String) session.getAttribute("uid");
        PreparedStatement ps = c.prepareStatement("SELECT name, email FROM users WHERE id = ?");
        ps.setString(1, uid);
        return ps.executeQuery();
    }
}
