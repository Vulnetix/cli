package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;

public class AdminController {
    @GetMapping("/admin")
~>    public String admin(@CookieValue(value = "role", defaultValue = "user") String role) {
        if ("admin".equals(role)) {
            return "admin";
        }
        return "denied";
    }

    boolean isAdmin(HttpServletRequest request) {
        for (Cookie c : request.getCookies()) {
~>            if (c.getName().equals("isAdmin") && c.getValue().equals("true")) {
                return true;
            }
        }
        return false;
    }
}
