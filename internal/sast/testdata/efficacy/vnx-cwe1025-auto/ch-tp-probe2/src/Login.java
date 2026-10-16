package com.acme;

public class Login {
    public boolean check(HttpServletRequest request, String expected) {
        String role = request.getParameter("role");
        if (role == "admin") {
            return true;
        }
~>        return request.getHeader("X-Token") == expected;
    }
}
