package com.acme;
import javax.servlet.http.*;
public class ConstServlet extends HttpServlet {
    private static final String HOME = "/home";
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String q = request.getParameter("q");
        log(q);
        response.setHeader("Cache-Control", "no-store");
        response.addHeader("X-Frame-Options", "DENY");
        response.sendRedirect(HOME);
    }
}
