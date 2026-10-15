package com.acme.admin;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SettingsServlet extends HttpServlet {
    private final DataSourceHolder holder = new DataSourceHolder();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        System.setProperty("http.proxyHost", request.getParameter("proxy"));
        String catalog = request.getParameter("catalog");
        try (Connection conn = holder.get()) {
~>            conn.setCatalog(catalog);
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}
