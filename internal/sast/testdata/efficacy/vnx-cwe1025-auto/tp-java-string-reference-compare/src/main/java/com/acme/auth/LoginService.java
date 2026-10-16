package com.acme.auth;

import jakarta.servlet.http.HttpServletRequest;

public class LoginService {

    private final UserRepository users;

    public LoginService(UserRepository users) {
        this.users = users;
    }

    public boolean isAdmin(HttpServletRequest request) {
        return request.getParameter("role") == "admin";
    }

    public boolean login(String username, String password) {
        String stored = users.passwordFor(username);
        if (stored == null) {
            return false;
        }
~>        return password == stored;
    }

    public boolean sameReferer(String referer, String host) {
        if (referer != "NULL" && referer.endsWith(host)) {
            return true;
        }
        return "self" == referer.trim();
    }

    public String sortOrDefault(String sortOrder) {
        if (sortOrder == null || sortOrder == "") {
            return "id";
        }
        return sortOrder;
    }

    public boolean sameAccount(Integer a, Integer b) {
        Integer left = a;
        Integer right = b;
~>        return left == right;
    }

    public boolean otpMatches(HttpServletRequest request, String expected) {
        String supplied = request.getHeader("X-OTP")
            .trim();
        return expected
~>            == supplied;
    }
}
