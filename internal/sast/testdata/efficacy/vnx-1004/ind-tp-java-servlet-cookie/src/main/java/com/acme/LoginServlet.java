package com.acme;

import jakarta.servlet.http.*;
import java.io.IOException;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse response) throws IOException {
        String token = Tokens.issue(req.getParameter("user"));
~>        Cookie cookie = new Cookie("access_token", token);
        cookie.setPath("/");
        cookie.setSecure(true);
        response.addCookie(cookie);
    }
}
