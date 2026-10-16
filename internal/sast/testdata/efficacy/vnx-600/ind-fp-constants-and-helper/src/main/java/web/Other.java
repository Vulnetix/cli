package web;

import java.io.IOException;
import javax.servlet.http.*;

public class Other extends HttpServlet {
    private static final int LIMIT = Integer.parseInt(System.getProperty("limit", "10"));

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int n = Integer.parseInt("42");
        // int bad = Integer.parseInt(request.getParameter("id"));
        String doc = "Integer.parseInt(request.getParameter(\"id\"))";
        response.getWriter().println(n + LIMIT);
    }
}
