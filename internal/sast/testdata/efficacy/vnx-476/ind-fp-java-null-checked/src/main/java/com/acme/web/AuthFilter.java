package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class AuthFilter {
    public String token(HttpServletRequest req) {
        String auth = req.getHeader("Authorization");
        if (auth == null || auth.isEmpty()) {
            return null;
        }
        return auth.substring(7);
    }
}
