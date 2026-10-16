package com.acme.profile;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

public class ProfileServlet extends HttpServlet {
    private DataSource ds;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession session = req.getSession(false);
        Long accountId = (Long) session.getAttribute("accountId");
        try (Connection c = ds.getConnection()) {
            PreparedStatement ps = c.prepareStatement("SELECT display_name, email FROM accounts WHERE id = ?");
            ps.setLong(1, accountId);
            ps.executeQuery();
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}
