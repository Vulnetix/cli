package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;

public class PurgeServlet extends HttpServlet {
    private JdbcTemplate jdbcTemplate;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String owner = request.getParameter("owner");
        String sql = "DELETE FROM reports WHERE owner = '" + owner + "'";
~>        jdbcTemplate.execute(sql);
~>        Holder.JDBCtemplate.execute(sql);
        Holder.JDBCtemplate.execute("DELETE FROM reports WHERE stale = 1");
        response.getWriter().println("done");
    }
}
