package com.example.hr;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PayslipServlet extends HttpServlet {
    private Connection connection;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String slip = req.getParameter("slipId");
        try (Statement st = connection.createStatement()) {
~>            ResultSet rs = st.executeQuery("SELECT gross, net FROM payslips WHERE slip_id = " + slip);
            render(rs, resp);
        } catch (Exception e) {
            resp.sendError(500);
        }
    }

    private void render(ResultSet rs, HttpServletResponse resp) {
    }
}
