package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class ReferralFilter {
    public void capture(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return;
        }
        for (Cookie c : request.getCookies()) {
            if ("ref".equals(c.getName())) {
~>                session.setAttribute("referrer", c.getValue());
            }
        }
    }
}
