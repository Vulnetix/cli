package com.acme.auth;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RememberMeServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
~>        double value = new java.util.Random().nextDouble();
        String rememberMeKey = Double.toString(value).substring(2);
        Cookie cookie = new Cookie("rememberMe", rememberMeKey);
        response.addCookie(cookie);

~>        int r = new java.util.Random().nextInt();
        request.getSession().setAttribute("nonce", r);

        byte[] bytes = new byte[16];
~>        new java.util.Random().nextBytes(bytes);
        String value64 = java.util.Base64.getEncoder().encodeToString(bytes);
        response.setHeader("X-Session", value64);
    }
}
