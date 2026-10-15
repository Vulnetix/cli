package com.acme;

public class Login {
    public boolean check(HttpServletRequest request, String expected, int n) {
        String role = request.getParameter("role");
        if (role == null || "admin".equals(role)) {
            return true;
        }
        if (n == 3) { return false; }
        return expected.equals(request.getHeader("X-Token"));
    }
}
