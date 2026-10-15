package com.shop.web;

import javax.servlet.http.HttpServletRequest;

public class AuthFilter {
    boolean allowed(HttpServletRequest req) {
        String auth = req.getHeader("Authorization");
        String scheme = "Bearer";
~>        if (auth.startsWith(scheme)) {
            return true;
        }
        return false;
    }
}
