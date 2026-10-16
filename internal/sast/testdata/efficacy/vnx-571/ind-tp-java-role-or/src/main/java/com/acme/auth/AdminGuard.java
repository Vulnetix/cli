package com.acme.auth;

public class AdminGuard {
    private static final String ROLE_ADMIN = "admin";
    private static final String ROLE_OWNER = "owner";

    public void requireAdmin(User user) {
        String role = user.getRole();
~>        if (role != ROLE_ADMIN || role != ROLE_OWNER) {
            throw new SecurityException("forbidden");
        }
    }
}
