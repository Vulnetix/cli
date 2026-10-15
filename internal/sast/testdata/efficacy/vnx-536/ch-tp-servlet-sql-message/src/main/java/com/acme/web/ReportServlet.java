package com.acme.web;

import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            run(request);
        } catch (SQLException ex) {
~>            response.getWriter().println("Error: " + ex.getMessage());
        }
    }
}
