package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class ModeCheck {
    public boolean isAdmin(HttpServletRequest request) {
~>        return request.getParameter("mode") == "admin";
    }
}
