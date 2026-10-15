package com.acme.web;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HealthServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String url = System.getenv("DATABASE_URL");
        String home = System.getProperty("user.home");
        File cache = new File(home, ".acme-cache");
        PrintWriter out = resp.getWriter();
        try (Connection c = DriverManager.getConnection(url)) {
            out.println("database: ok");
        } catch (Exception e) {
            out.println("database: down");
        }
        out.println("cache present: " + cache.exists());
    }
}
