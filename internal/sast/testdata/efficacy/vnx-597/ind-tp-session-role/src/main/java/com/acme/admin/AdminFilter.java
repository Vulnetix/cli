package com.acme.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class AdminFilter {

    public boolean allow(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }
        String role = (String) session.getAttribute("role");
~>        if (role != "admin" && role != "owner") {
            return false;
        }
        return true;
    }
}
