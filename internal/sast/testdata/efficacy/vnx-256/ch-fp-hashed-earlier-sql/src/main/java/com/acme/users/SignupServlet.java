package com.acme.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SignupServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String user = req.getParameter("username");
        String stored = encoder.encode(req.getParameter("password"));
        try (Connection c = ds.getConnection()) {
            PreparedStatement ps = c.prepareStatement("INSERT INTO accounts (username, password) VALUES (?, ?)");
            ps.setString(1, user);
            ps.setString(2, stored);
            ps.executeUpdate();
        }
    }
}
