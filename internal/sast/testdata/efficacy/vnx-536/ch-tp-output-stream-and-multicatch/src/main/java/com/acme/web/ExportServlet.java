package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import javax.servlet.http.*;

public class ExportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter writer = response.getWriter();
        try {
            export(request, writer);
        } catch (IOException | SQLException e) {
~>            writer.print(e);
        }
        try {
            other();
        } catch (RuntimeException ex) {
~>            response.getOutputStream().write(ex.getMessage().getBytes());
        }
    }
}
