package com.shop.servlet;

import javax.servlet.http.HttpServlet;
import java.sql.*;

public class LoginServlet extends HttpServlet {

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String user = req.getParameter("user");
        try (Connection conn = DriverManager.getConnection(URL)) {
~>            PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE name = ?");
            ps.setString(1, user);
            ResultSet rs = ps.executeQuery();
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}
