package com.acme;
import javax.servlet.http.*;
public class SafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String lang = request.getParameter("lang");
        String clean = lang.replaceAll("[\\r\\n]", "");
        response.setHeader("Content-Language", clean);
    }
}
