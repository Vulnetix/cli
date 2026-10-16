package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;

public class ReportServlet extends HttpServlet {
    private JdbcTemplate jdbcTemplate;
    private JdbcTemplate reportingJdbcTemplate;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String owner = request.getParameter("owner");
        String sql = "DELETE FROM reports WHERE owner = '" + owner + "'";
        jdbcTemplate.execute(sql);
        Holder.JDBCtemplate.execute(sql);
        reportingJdbcTemplate.execute("VACUUM reports_" + request.getHeader("X-Tenant"));
        response.getWriter().println("done");
    }
}
