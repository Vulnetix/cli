package app;

import javax.servlet.http.*;

public class AdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
~>        if ("true".equals(request.getParameter("isAdmin"))) {
            showAdmin(response);
        }
    }
    private void showAdmin(HttpServletResponse r) {}
}
