package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;

public class Login extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
~>        response.sendRedirect(next);
    }
}
