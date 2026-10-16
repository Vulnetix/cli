package com.acme;
import javax.servlet.http.*;
public class LangServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String lang = request.getParameter("lang");
~>        response.setHeader("Content-Language", lang);
    }
}
