package com.acme.web;

import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        try {
            out.println(render(request));
        } catch (SQLException sqle) {
~>            out.println("<p>Query failed: " + sqle.getMessage() + "</p>");
        } catch (Exception e) {
~>            response.sendError(500, e.getLocalizedMessage());
        } catch (Throwable t) {
~>            out.print(t);
        }
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            update(request);
        } catch (Exception e) {
~>            e.printStackTrace(new PrintWriter(response.getOutputStream()));
        }
    }
}
