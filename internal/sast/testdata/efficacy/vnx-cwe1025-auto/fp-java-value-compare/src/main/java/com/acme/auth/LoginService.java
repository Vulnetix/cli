package com.acme.auth;

import java.security.MessageDigest;
import java.util.Objects;
import jakarta.servlet.http.HttpServletRequest;

public class LoginService {

    enum Role { ADMIN, USER }

    public boolean isAdmin(HttpServletRequest request) {
        return "admin".equals(request.getParameter("role"));
    }

    public boolean login(String username, String password, byte[] expected, byte[] actual) {
        String stored = lookup(username);
        if (stored == null || password == null) {
            return false;
        }
        if (stored.length() == password.length() && count == 3) {
            log("lengths match == expected");
        }
        return Objects.equals(password, stored) && MessageDigest.isEqual(expected, actual);
    }

    public boolean sameRole(Role a, Role b, int x, char c) {
        // enums, primitives and chars compare by value with ==
        return a == b && x == 42 && c == 'y' && a == Role.ADMIN;
    }

    public boolean interned(String a, String b) {
        return a.intern() == b.intern();
    }

    public boolean typed(Object o) {
        return o instanceof TrustedPlugin && o.getClass() == TrustedPlugin.class;
    }

    private int count;

    private String lookup(String user) {
        String sql = "SELECT pw FROM users WHERE name = ?"; // "a" == b in a comment
        return sql;
    }

    private void log(String s) {
        System.out.println("check: role == \"admin\" failed");
    }
}
