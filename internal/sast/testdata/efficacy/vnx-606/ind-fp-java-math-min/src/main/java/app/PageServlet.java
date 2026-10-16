package app;

import javax.servlet.http.*;

public class PageServlet extends HttpServlet {
    private static final int MAX_ROWS = 500;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        int rows = Integer.parseInt(request.getParameter("rows"));
        rows = Math.min(rows, MAX_ROWS);
        for (int i = 0; i < rows; i++) {
            response.getWriter().println(i);
        }
    }
}
