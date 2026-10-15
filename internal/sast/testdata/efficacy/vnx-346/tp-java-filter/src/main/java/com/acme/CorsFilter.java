package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CorsFilter {
    void apply(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");
~>        if (origin != null && origin.contains("example.com")) {
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
~>        if (request.getHeader("Referer").startsWith("https://admin.example.com")) {
            grantAdminView(response);
        }
    }
}
